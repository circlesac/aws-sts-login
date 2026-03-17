import { execSync } from "child_process";
import { homedir } from "os";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import * as OTPAuth from "otpauth";

// Profile from CLI arg: aws-sts-login aws-china-prd
const profileArg = process.argv[2];
if (!profileArg) {
  console.log("Usage: aws-sts-login <profile>\n");
  console.log("Profiles configured in .env with prefix convention:");
  console.log("  AWS_CHINA_PRD_ACCOUNT_ID, _USERNAME, _PASSWORD, _MFA_SECRET, _REGION\n");
  const prefixes = new Set<string>();
  for (const key of Object.keys(process.env)) {
    const match = key.match(/^(.+)_ACCOUNT_ID$/);
    if (match) prefixes.add(match[1]);
  }
  if (prefixes.size > 0) {
    console.log("Available profiles:");
    for (const p of prefixes) {
      const name = p.toLowerCase().replace(/_/g, "-");
      console.log(`  ${name}  (${process.env[`${p}_ACCOUNT_ID`]})`);
    }
  }
  process.exit(0);
}

// Convert profile name to env prefix: aws-china-prd → AWS_CHINA_PRD
const envPrefix = profileArg.toUpperCase().replace(/-/g, "_");

function env(suffix: string, required = true): string {
  const val = process.env[`${envPrefix}_${suffix}`];
  if (!val && required) {
    console.error(`Missing env: ${envPrefix}_${suffix}`);
    process.exit(1);
  }
  return val || "";
}

const ACCOUNT_ID = env("ACCOUNT_ID");
const USERNAME = env("USERNAME");
const PASSWORD = env("PASSWORD");
const MFA_SECRET = env("MFA_SECRET", false);
const REGION = env("REGION", false) || "us-east-1";
const PROFILE = profileArg;

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
