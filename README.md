# aws-sts-login

AWS Console auto-login CLI — logs in via browser automation, obtains STS temporary credentials, and writes them to `~/.aws/credentials`.

## Install

```sh
brew install circlesac/tap/aws-sts-login
```

Or with npm:

```sh
npm install -g @circlesac/aws-sts-login
```

Or direct download:

```sh
curl -fsSL https://github.com/circlesac/aws-sts-login/releases/latest/download/install.sh | sh
```

## Setup

Create `~/.aws/sts-login` with your login profiles:

```ini
[my-aws-dev]
account_id = 123456789012
username = myuser
password = mypassword
mfa_secret = BASE32SECRET
region = us-east-1
```

See [sts-login.example](sts-login.example) for a full example.

Set restrictive permissions:

```sh
chmod 600 ~/.aws/sts-login
```

## Usage

```sh
aws-sts-login my-aws-dev
```

List available profiles:

```sh
aws-sts-login
```

## How it works

1. Opens a browser and logs into the AWS Console (username/password/MFA)
2. Captures console session credentials via CDP
3. Creates a temporary IAM Access Key using the console session
4. Calls `sts get-session-token` with the Access Key + MFA to obtain proper STS credentials (12h TTL)
5. Deletes the Access Key immediately
6. Writes the STS credentials to `~/.aws/credentials` and creates a `~/.aws/config` profile if needed

On subsequent runs, cached credentials are reused until they expire.

## credential_process

Can also be used as `credential_process` in `~/.aws/config`:

```ini
[profile my-aws-dev]
credential_process = env CREDENTIAL_PROCESS=true aws-sts-login my-aws-dev
```

Note: This will open a browser window when credentials expire.
