import { execSync } from "child_process";
import { homedir } from "os";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
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

// Load profiles from ~/.aws/sts-login
const configPath = join(homedir(), ".aws", "sts-login");

function loadProfiles(): Record<string, Record<string, string>> {
  if (!existsSync(configPath)) return {};
  return parseIni(readFileSync(configPath, "utf-8"));
}

const profiles = loadProfiles();

// Profile from CLI arg: aws-sts-login aws-china-prd
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

      // Find page target
      if (msg.id === 1 && msg.result?.targetInfos) {
        const page = msg.result.targetInfos.find((t: any) => t.type === "page");
        if (page) send("Target.attachToTarget", { targetId: page.targetId, flatten: true });
      }

      // Enable network, navigate to trigger /tb/creds
      if (msg.id === 2 && msg.result?.sessionId) {
        sessionId = msg.result.sessionId;
        send("Network.enable", {}, sessionId);
        setTimeout(() => {
          for (const svc of ["iam", "s3", "ec2"]) {
            send("Page.navigate", { url: `https://${CONSOLE_DOMAIN}/${svc}/home` }, sessionId);
            break; // navigate to first, listen for response
          }
        }, 300);
      }

      // Detect /tb/creds response
      if (msg.method === "Network.responseReceived" && msg.params?.response?.url?.includes("/tb/creds")) {
        const resp = msg.params.response;
        if (resp.status === 200 && resp.mimeType === "application/json") {
          credRequestId = msg.params.requestId;
          setTimeout(() => send("Network.getResponseBody", { requestId: credRequestId }, sessionId), 1000);
        }
      }

      // Get response body
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
  console.log(`[${PROFILE}] ${SIGNIN_URL} (${USERNAME})`);

  // Open login page
  ab(`--headed open "${SIGNIN_URL}"`);

  // Wait for login form and fill
  await sleep(2000);
  let snapshot = ab("snapshot -i");

  if (snapshot.includes("username") || snapshot.includes("IAM user")) {
    ab(`fill "#username" "${USERNAME}"`);
    ab(`fill "#password" "${PASSWORD}"`);
    ab(`click "#signin_button"`);
  }

  // MFA
  if (MFA_SECRET) {
    await sleep(3000);
    snapshot = ab("snapshot -i");

    if (snapshot.includes("MFA") || snapshot.includes("mfacode") || snapshot.includes("mfaCode")) {
      const code = generateMFACode()!;
      console.log(`MFA: ${code}`);

      // Try known MFA selectors
      const mfaSel = snapshot.includes("mfacode") ? "#mfacode" : "[name='mfaCode']";
      try {
        ab(`fill "${mfaSel}" "${code}"`);
      } catch {
        ab(`fill "#mfacode" "${code}"`);
      }

      // Click submit
      try {
        ab('click "#submitMfa_button"');
      } catch {
        try {
          ab('click "button[type=submit]"');
        } catch {}
      }
    }
  }

  // Wait for console home
  for (let i = 0; i < 20; i++) {
    await sleep(3000);
    try {
      const url = ab("get url");
      if (url.includes("/console/home")) break;
    } catch {}
  }

  // Capture credentials via CDP
  let credentials: any;
  try {
    credentials = await captureCredsViaCDP();
    console.log(`[CAPTURE] expires: ${credentials.expiration || credentials.Expiration || "unknown"}`);
  } catch (err: any) {
    // Retry with other services
    for (const svc of ["s3", "ec2"]) {
      try {
        ab(`open "https://${CONSOLE_DOMAIN}/${svc}/home"`);
        credentials = await captureCredsViaCDP();
        if (credentials) break;
      } catch {}
    }
  }

  ab("close");

  if (!credentials) {
    console.error("Failed to capture credentials.");
    process.exit(1);
  }

  const creds = {
    accessKeyId: credentials.accessKeyId || credentials.AccessKeyId,
    secretAccessKey: credentials.secretAccessKey || credentials.SecretAccessKey,
    sessionToken: credentials.sessionToken || credentials.SessionToken,
    expiration: credentials.expiration || credentials.Expiration || "unknown",
  };

  // credential_process mode: output JSON to stdout
  if (process.env.CREDENTIAL_PROCESS === "true") {
    process.stdout.write(JSON.stringify({
      Version: 1,
      AccessKeyId: creds.accessKeyId,
      SecretAccessKey: creds.secretAccessKey,
      SessionToken: creds.sessionToken,
      Expiration: creds.expiration,
    }));
    return;
  }

  // Write to ~/.aws/credentials
  const credPath = join(homedir(), ".aws", "credentials");
  let content = existsSync(credPath) ? readFileSync(credPath, "utf-8") : "";
  content = content.replace(new RegExp(`\\[${PROFILE}\\][\\s\\S]*?(?=\\n\\[|$)`, "g"), "").trim();
  const section = [
    "",
    "",
    `[${PROFILE}]`,
    `aws_access_key_id = ${creds.accessKeyId}`,
    `aws_secret_access_key = ${creds.secretAccessKey}`,
    `aws_session_token = ${creds.sessionToken}`,
    `region = ${REGION}`,
    `# expires: ${creds.expiration}`,
    "",
  ].join("\n");
  content += section;
  writeFileSync(credPath, content);

  console.log(`Done! [${PROFILE}] → ${credPath}`);
  console.log(`Test: aws s3 ls --profile ${PROFILE} --region ${REGION}`);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
