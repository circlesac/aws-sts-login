# aws-sts-login

AWS Console auto-login CLI — captures STS temporary credentials via [agent-browser](https://agent-browser.dev/) and CDP.

## Install

```sh
npm install -g @circlesac/aws-sts-login
```

Or with Homebrew:

```sh
brew install circlesac/tap/aws-sts-login
```

Or direct download:

```sh
curl -fsSL https://github.com/circlesac/aws-sts-login/releases/latest/download/install.sh | sh
```

Requires `agent-browser` (auto-installed via npm, or `npm install -g agent-browser`).

## Setup

Copy `.env.example` to `.env` and fill in your credentials:

```bash
# Profile: my-aws-dev → prefix: MY_AWS_DEV
MY_AWS_DEV_ACCOUNT_ID=123456789012
MY_AWS_DEV_USERNAME=myuser
MY_AWS_DEV_PASSWORD=mypassword
MY_AWS_DEV_MFA_SECRET=BASE32SECRET
MY_AWS_DEV_REGION=us-east-1
```

Profile naming: `my-aws-dev` → prefix `MY_AWS_DEV`

## Usage

As `credential_process` in `~/.aws/config`:

```ini
[profile my-aws-dev]
credential_process = env CREDENTIAL_PROCESS=true aws-sts-login my-aws-dev
```

Or run directly to write credentials to `~/.aws/credentials`:

```sh
aws-sts-login my-aws-dev
```
