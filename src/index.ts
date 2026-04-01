import { execSync } from "child_process";
import { homedir } from "os";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import * as OTPAuth from "otpauth";

// Parse INI-style config file
function parseIni(content: string): Record<string, Record<string, string>> {
  const result: Record<string, Record<string, string>> = {};
  let currentSection = "";
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const sectionMatch = trimmed.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      result[currentSection] = result[currentSection] || {};
      continue;
    }
    const kvMatch = trimmed.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (kvMatch && currentSection) {
      result[currentSection][kvMatch[1].trim()] = kvMatch[2].trim();
    }
  }
  return result;
}

const configPath = join(homedir(), ".aws", "sts-login");
const credPath = join(homedir(), ".aws", "credentials");

function loadProfiles(): Record<string, Record<string, string>> {
  if (!existsSync(configPath)) return {};
  return parseIni(readFileSync(configPath, "utf-8"));
}

const profiles = loadProfiles();

const profileArg = process.argv[2];
if (!profileArg) {
  console.log("Usage: aws-sts-login <profile>\n");
  console.log(`Profiles configured in ${configPath}:\n`);
  const names = Object.keys(profiles);
  if (names.length > 0) {
    console.log("Available profiles:");
    for (const name of names) {
      console.log(`  ${name}  (${profiles[name].account_id || ""})`);
    }
  } else {
    console.log("No profiles found. Create ~/.aws/sts-login with:");
    console.log("  [aws-china-prd]");
    console.log("  account_id = 123456789012");
    console.log("  username = myuser");
    console.log("  password = mypass");
    console.log("  mfa_secret = BASE32SECRET");
    console.log("  region = cn-north-1");
  }
  process.exit(0);
}

const profile = profiles[profileArg];
if (!profile) {
  console.error(`Profile "${profileArg}" not found in ${configPath}`);
  console.error(`Available: ${Object.keys(profiles).join(", ") || "(none)"}`);
  process.exit(1);
}

const ACCOUNT_ID = profile.account_id;
const USERNAME = profile.username;
const PASSWORD = profile.password;
const MFA_SECRET = profile.mfa_secret || "";
const REGION = profile.region || "us-east-1";
const PROFILE = profileArg;

if (!ACCOUNT_ID || !USERNAME || !PASSWORD) {
  console.error(`Profile "${profileArg}" missing required fields (account_id, username, password)`);
  process.exit(1);
}

const isChina = profileArg.includes("china");
const DOMAIN = isChina ? "amazonaws.cn" : "aws.amazon.com";
const CONSOLE_DOMAIN = isChina ? "console.amazonaws.cn" : "console.aws.amazon.com";
const SIGNIN_URL = `https://${ACCOUNT_ID}.signin.${DOMAIN}/console`;
const mfaArn = `arn:${isChina ? "aws-cn" : "aws"}:iam::${ACCOUNT_ID}:mfa/${USERNAME}`;

function generateMFACode(): string | null {
  if (!MFA_SECRET) return null;
  return new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(MFA_SECRET),
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  }).generate();
}

function ab(cmd: string): string {
  return execSync(`npx agent-browser ${cmd}`, { encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] }).trim();
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function aws(cmd: string, env?: Record<string, string>): string {
  const envStr = env ? Object.entries(env).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" ") : "";
  const fullCmd = envStr ? `env ${envStr} aws ${cmd}` : `aws ${cmd}`;
  return execSync(fullCmd, { encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] }).trim();
}

function saveCredentials(stsCreds: any) {
  let content = existsSync(credPath) ? readFileSync(credPath, "utf-8") : "";
  content = content.replace(new RegExp(`\\[${PROFILE}\\][\\s\\S]*?(?=\\n\\[|$)`, "g"), "").trim();
  const section = [
    "",
    "",
    `[${PROFILE}]`,
    `aws_access_key_id = ${stsCreds.AccessKeyId}`,
    `aws_secret_access_key = ${stsCreds.SecretAccessKey}`,
    `aws_session_token = ${stsCreds.SessionToken}`,
    `region = ${REGION}`,
    `# expires: ${stsCreds.Expiration}`,
    "",
  ].join("\n");
  content += section;
  writeFileSync(credPath, content);
}

async function captureCredsViaCDP(): Promise<any> {
  const cdpUrl = ab("get cdp-url");

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(cdpUrl);
    let id = 1;
    let sessionId = "";
    let credRequestId = "";
    const timeout = setTimeout(() => { ws.close(); reject(new Error("CDP timeout")); }, 30000);

    function send(method: string, params: Record<string, any> = {}, sid?: string) {
      const msg: any = { id: id++, method, params };
      if (sid) msg.sessionId = sid;
      ws.send(JSON.stringify(msg));
      return msg.id;
    }

    ws.onopen = () => send("Target.getTargets");

    ws.onmessage = (e) => {
      const msg = JSON.parse(String(e.data));

      if (msg.id === 1 && msg.result?.targetInfos) {
        const page = msg.result.targetInfos.find((t: any) => t.type === "page");
        if (page) send("Target.attachToTarget", { targetId: page.targetId, flatten: true });
      }

      if (msg.id === 2 && msg.result?.sessionId) {
        sessionId = msg.result.sessionId;
        send("Network.enable", {}, sessionId);
        setTimeout(() => {
          send("Page.navigate", { url: `https://${CONSOLE_DOMAIN}/iam/home` }, sessionId);
        }, 300);
      }

      if (msg.method === "Network.responseReceived" && msg.params?.response?.url?.includes("/tb/creds")) {
        const resp = msg.params.response;
        if (resp.status === 200 && resp.mimeType === "application/json") {
          credRequestId = msg.params.requestId;
          setTimeout(() => send("Network.getResponseBody", { requestId: credRequestId }, sessionId), 1000);
        }
      }

      if (msg.result?.body && credRequestId) {
        clearTimeout(timeout);
        try {
          resolve(JSON.parse(msg.result.body));
        } catch {
          reject(new Error("Failed to parse /tb/creds response"));
        }
        ws.close();
      }
    };

    ws.onerror = (e) => { clearTimeout(timeout); reject(e); };
  });
}

async function main() {
  console.log(`[${PROFILE}] account:${ACCOUNT_ID} user:${USERNAME} region:${REGION}`);

  // Check if existing STS credentials are still valid
  if (existsSync(credPath)) {
    const content = readFileSync(credPath, "utf-8");
    const expiresMatch = content.match(new RegExp(`\\[${PROFILE}\\][\\s\\S]*?# expires: (.+)`));
    if (expiresMatch) {
      const expiration = new Date(expiresMatch[1].trim());
      if (expiration > new Date()) {
        console.log(`[CACHED] Credentials still valid until ${expiration.toISOString()}`);
        return;
      }
    }
  }

  // Browser login
  console.log(`[BROWSER] ${SIGNIN_URL} (${USERNAME})`);
  ab(`--headed open "${SIGNIN_URL}"`);

  await sleep(2000);
  let snapshot = ab("snapshot -i");

  if (snapshot.includes("username") || snapshot.includes("IAM user")) {
    ab(`fill "#username" "${USERNAME}"`);
    ab(`fill "#password" "${PASSWORD}"`);
    ab(`click "#signin_button"`);
  }

  if (MFA_SECRET) {
    await sleep(3000);
    snapshot = ab("snapshot -i");

    if (snapshot.includes("MFA") || snapshot.includes("mfacode") || snapshot.includes("mfaCode")) {
      const code = generateMFACode()!;
      console.log(`[BROWSER] MFA: ${code}`);

      const mfaSel = snapshot.includes("mfacode") ? "#mfacode" : "[name='mfaCode']";
      try {
        ab(`fill "${mfaSel}" "${code}"`);
      } catch {
        ab(`fill "#mfacode" "${code}"`);
      }

      try {
        ab('click "#submitMfa_button"');
      } catch {
        try { ab('click "button[type=submit]"'); } catch {}
      }
    }
  }

  // Wait for console
  for (let i = 0; i < 20; i++) {
    await sleep(3000);
    try {
      const url = ab("get url");
      if (url.includes("/console/home") || url.includes("/console/")) break;
    } catch {}
  }

  // Capture console credentials via CDP
  console.log("[BROWSER] Capturing console session...");
  const consoleCreds = await captureCredsViaCDP();

  ab("close");

  if (!consoleCreds) {
    console.error("Failed to capture console credentials.");
    process.exit(1);
  }

  const consoleEnv: Record<string, string> = {
    AWS_ACCESS_KEY_ID: consoleCreds.accessKeyId || consoleCreds.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: consoleCreds.secretAccessKey || consoleCreds.SecretAccessKey,
    AWS_SESSION_TOKEN: consoleCreds.sessionToken || consoleCreds.SessionToken,
  };

  // Create temporary access key (delete existing ones first to stay under limit)
  const listKeysOutput = aws(`iam list-access-keys --user-name ${USERNAME} --region ${REGION} --output json`, consoleEnv);
  const existingKeys = JSON.parse(listKeysOutput).AccessKeyMetadata || [];

  if (existingKeys.length >= 2) {
    const oldest = existingKeys.sort((a: any, b: any) => new Date(a.CreateDate).getTime() - new Date(b.CreateDate).getTime())[0];
    console.log(`[IAM] Deleting access key ${oldest.AccessKeyId} (limit reached)...`);
    aws(`iam delete-access-key --user-name ${USERNAME} --access-key-id ${oldest.AccessKeyId} --region ${REGION}`, consoleEnv);
  }

  const createKeyOutput = aws(`iam create-access-key --user-name ${USERNAME} --region ${REGION} --output json`, consoleEnv);
  const newKey = JSON.parse(createKeyOutput).AccessKey;
  console.log(`[IAM] Created access key ${newKey.AccessKeyId}`);

  // Wait for key propagation
  await sleep(10000);

  // Get STS session token with MFA
  const stsEnv: Record<string, string> = {
    AWS_ACCESS_KEY_ID: newKey.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: newKey.SecretAccessKey,
  };

  let stsCmd = `sts get-session-token --region ${REGION} --output json`;
  if (MFA_SECRET) {
    const mfaCode = generateMFACode()!;
    stsCmd += ` --serial-number ${mfaArn} --token-code ${mfaCode}`;
  }

  let stsOutput: string;
  try {
    stsOutput = aws(stsCmd, stsEnv);
  } catch (err: any) {
    if (MFA_SECRET && err.message?.includes("MultiFactorAuthentication")) {
      console.log("[STS] Waiting for next MFA window...");
      await sleep(30000);
      const freshCode = generateMFACode()!;
      stsCmd = `sts get-session-token --region ${REGION} --output json --serial-number ${mfaArn} --token-code ${freshCode}`;
      stsOutput = aws(stsCmd, stsEnv);
    } else {
      throw err;
    }
  }

  const stsCreds = JSON.parse(stsOutput).Credentials;
  console.log(`[STS] Session token expires: ${stsCreds.Expiration}`);

  // Delete the access key immediately
  try {
    aws(`iam delete-access-key --user-name ${USERNAME} --access-key-id ${newKey.AccessKeyId} --region ${REGION}`, stsEnv);
    console.log(`[IAM] Deleted access key ${newKey.AccessKeyId}`);
  } catch {
    // Try with console creds if STS creds can't delete
    try {
      aws(`iam delete-access-key --user-name ${USERNAME} --access-key-id ${newKey.AccessKeyId} --region ${REGION}`, consoleEnv);
      console.log(`[IAM] Deleted access key ${newKey.AccessKeyId}`);
    } catch {
      console.log(`[IAM] Warning: could not delete access key ${newKey.AccessKeyId}`);
    }
  }

  // Save credentials
  saveCredentials(stsCreds);

  if (process.env.CREDENTIAL_PROCESS === "true") {
    process.stdout.write(JSON.stringify({
      Version: 1,
      AccessKeyId: stsCreds.AccessKeyId,
      SecretAccessKey: stsCreds.SecretAccessKey,
      SessionToken: stsCreds.SessionToken,
      Expiration: stsCreds.Expiration,
    }));
    return;
  }

  console.log(`Done! [${PROFILE}] → ${credPath}`);
  console.log(`Test: aws s3 ls --profile ${PROFILE} --region ${REGION}`);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
