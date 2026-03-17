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

As `credential_process` in `~/.aws/config`:

```ini
[profile my-aws-dev]
credential_process = env CREDENTIAL_PROCESS=true aws-sts-login my-aws-dev
```

Or run directly to write credentials to `~/.aws/credentials`:

```sh
aws-sts-login my-aws-dev
```

List available profiles:

```sh
aws-sts-login
```
