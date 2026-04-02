import { defineCommand, runMain } from "citty";
import { execSync } from "child_process";
import { homedir } from "os";
import { readFileSync, writeFileSync, existsSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
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

function updateIniValue(filePath: string, section: string, key: string, value: string) {
  let content = readFileSync(filePath, "utf-8");
  const sectionHeader = `[${section}]`;
  const sectionIdx = content.indexOf(sectionHeader);
  if (sectionIdx === -1) throw new Error(`Section [${section}] not found in ${filePath}`);

  const afterSection = content.indexOf("\n[", sectionIdx + sectionHeader.length);
  const sectionEnd = afterSection === -1 ? content.length : afterSection;
  const sectionContent = content.slice(sectionIdx, sectionEnd);

  const keyRegex = new RegExp(`^${key}\\s*=.*$`, "m");
  let newSectionContent;
  if (keyRegex.test(sectionContent)) {
    newSectionContent = sectionContent.replace(keyRegex, `${key} = ${value}`);
  } else {
    newSectionContent = sectionContent.trimEnd() + `\n${key} = ${value}\n`;
  }

  content = content.slice(0, sectionIdx) + newSectionContent + content.slice(sectionEnd);
  writeFileSync(filePath, content);
}

const configPath = join(homedir(), ".aws", "sts-login");
const credPath = join(homedir(), ".aws", "credentials");

function loadProfiles(): Record<string, Record<string, string>> {
  if (!existsSync(configPath)) return {};
  return parseIni(readFileSync(configPath, "utf-8"));
}

const profiles = loadProfiles();

function profileDomains(profileName: string) {
  const isChina = profileName.includes("china");
  return {
    isChina,
    domain: isChina ? "amazonaws.cn" : "aws.amazon.com",
    consoleDomain: isChina ? "console.amazonaws.cn" : "console.aws.amazon.com",
    arnPrefix: isChina ? "aws-cn" : "aws",
  };
}

function generateMFACode(secret: string): string {
  return new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(secret),
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  }).generate();
}

function ab(cmd: string, retries = 3): string {
  for (let i = 0; i < retries; i++) {
    try {
      return execSync(`npx agent-browser ${cmd}`, { encoding: "utf-8", timeout: 60000, stdio: ["pipe", "pipe", "pipe"] }).trim();
    } catch (err: any) {
      if (i === retries - 1) throw err;
      console.log(`[BROWSER] Retrying (${i + 1}/${retries})...`);
    }
  }
  throw new Error("unreachable");
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function aws(cmd: string, env?: Record<string, string>): string {
  const envStr = env ? Object.entries(env).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" ") : "";
  const fullCmd = envStr ? `env ${envStr} aws ${cmd}` : `aws ${cmd}`;
  return execSync(fullCmd, { encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] }).trim();
}

function ensureConfigProfile(profileName: string, region: string) {
  const configFile = join(homedir(), ".aws", "config");
  const content = existsSync(configFile) ? readFileSync(configFile, "utf-8") : "";
  const profileHeader = `[profile ${profileName}]`;
  if (content.includes(profileHeader)) return;
  const section = [
    "",
    profileHeader,
    `region = ${region}`,
    "",
  ].join("\n");
  writeFileSync(configFile, content.trimEnd() + "\n" + section);
}

function saveCredentials(profileName: string, region: string, stsCreds: any) {
  ensureConfigProfile(profileName, region);
  let content = existsSync(credPath) ? readFileSync(credPath, "utf-8") : "";
  content = content.replace(new RegExp(`\\[${profileName}\\][\\s\\S]*?(?=\\n\\[|$)`, "g"), "").trim();
  const section = [
    "",
    "",
    `[${profileName}]`,
    `aws_access_key_id = ${stsCreds.AccessKeyId}`,
    `aws_secret_access_key = ${stsCreds.SecretAccessKey}`,
    `aws_session_token = ${stsCreds.SessionToken}`,
    `# expires: ${stsCreds.Expiration}`,
    "",
  ].join("\n");
  content += section;
  writeFileSync(credPath, content);
}

async function captureCredsViaCDP(consoleDomain: string): Promise<any> {
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
          send("Page.navigate", { url: `https://${consoleDomain}/iam/home` }, sessionId);
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

async function browserLogin(opts: {
  profileName: string;
  accountId: string;
  username: string;
  password: string;
  mfaSecret: string;
  region: string;
}): Promise<Record<string, string>> {
  const { consoleDomain, domain } = profileDomains(opts.profileName);
  const signinUrl = `https://${opts.accountId}.signin.${domain}/console`;

  console.log(`[BROWSER] ${signinUrl} (${opts.username})`);
  try { ab("close", 1); } catch {}
  await sleep(2000);
  try {
    ab(`--headed open "${signinUrl}"`, 1);
  } catch {
    // Page may still be loading — wait and continue
    await sleep(5000);
  }

  // Wait for login form to appear
  let snapshot = "";
  for (let i = 0; i < 10; i++) {
    await sleep(2000);
    try {
      snapshot = ab("snapshot -i", 1);
      if (snapshot.includes("username") || snapshot.includes("IAM user")) break;
    } catch {}
  }

  if (snapshot.includes("username") || snapshot.includes("IAM user")) {
    ab(`fill "#username" "${opts.username}"`);
    ab(`fill "#password" "${opts.password}"`);
    ab(`click "#signin_button"`);
  }

  if (opts.mfaSecret) {
    await sleep(3000);
    snapshot = ab("snapshot -i");

    if (snapshot.includes("MFA") || snapshot.includes("mfacode") || snapshot.includes("mfaCode")) {
      const code = generateMFACode(opts.mfaSecret);
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

  console.log("[BROWSER] Capturing console session...");
  const consoleCreds = await captureCredsViaCDP(consoleDomain);

  ab("close");

  if (!consoleCreds) {
    console.error("Failed to capture console credentials.");
    process.exit(1);
  }

  return {
    AWS_ACCESS_KEY_ID: consoleCreds.accessKeyId || consoleCreds.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: consoleCreds.secretAccessKey || consoleCreds.SecretAccessKey,
    AWS_SESSION_TOKEN: consoleCreds.sessionToken || consoleCreds.SessionToken,
  };
}

async function setupMfa(profileName: string, username: string, region: string, consoleEnv: Record<string, string>): Promise<string> {
  const { arnPrefix } = profileDomains(profileName);
  const mfaArn = `arn:${arnPrefix}:iam::${profiles[profileName].account_id}:mfa/${username}`;

  // Remove existing MFA device if any
  try {
    const mfaDevices = JSON.parse(aws(`iam list-mfa-devices --user-name ${username} --region ${region} --output json`, consoleEnv));
    for (const device of mfaDevices.MFADevices || []) {
      console.log(`[MFA] Removing existing MFA device`);
      aws(`iam deactivate-mfa-device --user-name ${username} --serial-number ${device.SerialNumber} --region ${region}`, consoleEnv);
      aws(`iam delete-virtual-mfa-device --serial-number ${device.SerialNumber} --region ${region}`, consoleEnv);
    }
  } catch {}

  // Clean up orphaned virtual MFA devices
  try {
    const allDevices = JSON.parse(aws(`iam list-virtual-mfa-devices --region ${region} --output json`, consoleEnv));
    for (const device of allDevices.VirtualMFADevices || []) {
      if (device.SerialNumber === mfaArn && !device.User) {
        console.log(`[MFA] Removing orphaned virtual MFA device`);
        aws(`iam delete-virtual-mfa-device --serial-number ${mfaArn} --region ${region}`, consoleEnv);
      }
    }
  } catch {}

  // Create virtual MFA device
  const seedFile = join(tmpdir(), `mfa-seed-${Date.now()}`);
  aws(`iam create-virtual-mfa-device --virtual-mfa-device-name ${username} --outfile ${seedFile} --bootstrap-method Base32StringSeed --region ${region} --output json`, consoleEnv);
  const mfaSecret = readFileSync(seedFile, "utf-8").trim();
  unlinkSync(seedFile);
  console.log(`[MFA] Virtual MFA device created`);

  // Generate two consecutive TOTP codes
  console.log("[MFA] Waiting for TOTP window...");
  const now = Math.floor(Date.now() / 1000);
  const waitSecs = 30 - (now % 30) + 1;
  await sleep(waitSecs * 1000);

  const code1 = generateMFACode(mfaSecret);
  console.log(`[MFA] Code 1: ${code1}`);
  await sleep(30000);
  const code2 = generateMFACode(mfaSecret);
  console.log(`[MFA] Code 2: ${code2}`);

  // Enable MFA device
  aws(
    `iam enable-mfa-device --user-name ${username} --serial-number ${mfaArn} --authentication-code1 ${code1} --authentication-code2 ${code2} --region ${region}`,
    consoleEnv,
  );
  console.log(`[MFA] MFA enabled for ${username}`);

  // Save to config
  updateIniValue(configPath, profileName, "mfa_secret", mfaSecret);
  console.log(`[MFA] mfa_secret saved to ${configPath}`);

  return mfaSecret;
}

const main = defineCommand({
  meta: {
    name: "aws-sts-login",
    description: "AWS Console auto-login CLI — captures STS temporary credentials via browser automation",
  },
  args: {
    profile: {
      type: "positional",
      description: "Profile name from ~/.aws/sts-login",
      required: false,
    },
  },
  async run({ args }) {
    if (!args.profile) {
      console.log(`Profiles configured in ${configPath}:\n`);
      const names = Object.keys(profiles);
      if (names.length > 0) {
        for (const name of names) {
          const mfa = profiles[name].mfa_secret ? "MFA" : "no MFA";
          console.log(`  ${name}  (${profiles[name].account_id || ""}) [${mfa}]`);
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
      return;
    }

    const profileName = args.profile;
    const profile = profiles[profileName];
    if (!profile) {
      console.error(`Profile "${profileName}" not found in ${configPath}`);
      console.error(`Available: ${Object.keys(profiles).join(", ") || "(none)"}`);
      process.exit(1);
    }

    const ACCOUNT_ID = profile.account_id;
    const USERNAME = profile.username;
    const PASSWORD = profile.password;
    let MFA_SECRET = profile.mfa_secret || "";
    const REGION = profile.region || "us-east-1";
    const { arnPrefix } = profileDomains(profileName);
    const mfaArn = `arn:${arnPrefix}:iam::${ACCOUNT_ID}:mfa/${USERNAME}`;

    if (!ACCOUNT_ID || !USERNAME || !PASSWORD) {
      console.error(`Profile "${profileName}" missing required fields (account_id, username, password)`);
      process.exit(1);
    }

    console.log(`[${profileName}] account:${ACCOUNT_ID} user:${USERNAME} region:${REGION}`);

    // Check if existing STS credentials are still valid
    if (existsSync(credPath)) {
      const content = readFileSync(credPath, "utf-8");
      const expiresMatch = content.match(new RegExp(`\\[${profileName}\\][\\s\\S]*?# expires: (.+)`));
      if (expiresMatch) {
        const expiration = new Date(expiresMatch[1].trim());
        if (expiration > new Date()) {
          console.log(`[CACHED] Credentials still valid until ${expiration.toISOString()}`);
          return;
        }
      }
    }

    // Browser login (without MFA if not configured yet)
    let consoleEnv = await browserLogin({
      profileName,
      accountId: ACCOUNT_ID,
      username: USERNAME,
      password: PASSWORD,
      mfaSecret: MFA_SECRET,
      region: REGION,
    });

    // Auto-setup MFA if not configured
    if (!MFA_SECRET) {
      console.log(`[MFA] No mfa_secret configured — setting up MFA automatically...`);
      MFA_SECRET = await setupMfa(profileName, USERNAME, REGION, consoleEnv);

      // Re-login with MFA — console session needs MFA context for IAM operations
      console.log(`[BROWSER] Re-logging in with MFA...`);
      consoleEnv = await browserLogin({
        profileName,
        accountId: ACCOUNT_ID,
        username: USERNAME,
        password: PASSWORD,
        mfaSecret: MFA_SECRET,
        region: REGION,
      });
    }

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
      const mfaCode = generateMFACode(MFA_SECRET);
      stsCmd += ` --serial-number ${mfaArn} --token-code ${mfaCode}`;
    }

    let stsOutput: string;
    try {
      stsOutput = aws(stsCmd, stsEnv);
    } catch (err: any) {
      if (MFA_SECRET && err.message?.includes("MultiFactorAuthentication")) {
        console.log("[STS] Waiting for next MFA window...");
        await sleep(30000);
        const freshCode = generateMFACode(MFA_SECRET);
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
      try {
        aws(`iam delete-access-key --user-name ${USERNAME} --access-key-id ${newKey.AccessKeyId} --region ${REGION}`, consoleEnv);
        console.log(`[IAM] Deleted access key ${newKey.AccessKeyId}`);
      } catch {
        console.log(`[IAM] Warning: could not delete access key ${newKey.AccessKeyId}`);
      }
    }

    // Save credentials
    saveCredentials(profileName, REGION, stsCreds);

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

    console.log(`Done! [${profileName}] → ${credPath}`);
    console.log(`Test: aws s3 ls --profile ${profileName} --region ${REGION}`);
  },
});

runMain(main);
