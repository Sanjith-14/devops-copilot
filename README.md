# DevOps Copilot

An **extensible, multi-account MCP server** that lets LLMs (Claude Desktop or any
[Model Context Protocol](https://modelcontextprotocol.io) client) safely operate on AWS
through natural language.

## What's here

- **Zero config files** — AWS accounts are auto-discovered from your `~/.aws`
  profiles (static keys, SSO, or role_arn/source_profile entries all work).
  Sign in with your normal AWS tooling; the server picks it up.
- **Core** — risk-tiered guardrails (read-only by default; writes require
  per-call user approval via MCP elicitation), multi-account AWS client
  factory, and a registry that auto-discovers service modules from
  `src/services/<name>/` at startup (zero core changes to add one).
- **S3 module** — 5 read tools: `list_buckets`, `check_bucket_public_access`,
  `check_bucket_encryption`, `list_objects`, `get_bucket_region`.
- **Core tools** — `list_accounts`, `list_modules`, `health_check`, and
  `assume_role` (registers a role as a temporary account, user-approved).

Every tool response is tagged with `_account` and `_region`, so multi-account
output is never ambiguous inside the LLM context.

## Quick start

```bash
npm install
npm run build
```

Sign in to AWS as usual (`aws configure`, or `aws configure sso` +
`aws sso login`), then wire it into Claude Desktop
(`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "devops-copilot": {
      "command": "node",
      "args": ["/absolute/path/to/devops-copilot/dist/core/server.js"],
      "env": { "DEVOPS_COPILOT_PROFILES": "my-dev-profile" }
    }
  }
}
```

Restart Claude Desktop and ask: *"List my S3 buckets and check whether any are public."*

### Environment variables (all optional)

| Variable | Default | Meaning |
| --- | --- | --- |
| `DEVOPS_COPILOT_PROFILES` | all discovered | Comma-separated allowlist of `~/.aws` profiles to expose |
| `DEVOPS_COPILOT_DEFAULT_PROFILE` | `default`, else first | Account used when a tool call omits `account` |
| `DEVOPS_COPILOT_SERVICES` | all | Which service modules to load |
| `DEVOPS_COPILOT_ALLOW_WRITE` | `false` | Permit mutate tools on clients without interactive approval |
| `DEVOPS_COPILOT_ALLOW_DESTRUCTIVE` | `false` | Gate for destructive tools (user approval still required) |
| `AWS_REGION` | `us-east-1` | Fallback region when a profile has none |

## Credentials & login

The server never handles passwords itself — it discovers and uses whatever is
in `~/.aws`. Three supported flows:

**Plain access keys** — `aws configure --profile <name>` once; nothing else needed.

**SSO (browser + MFA)** — `aws configure sso` once, then per session:

```bash
aws sso login --profile <name>
```

**MFA-gated IAM keys (terminal + TOTP)** — for profiles whose IAM policy
denies everything until an MFA session exists. The built-in `login`
subcommand mints temporary session credentials into a `[copilot-session]`
profile the server auto-discovers:

```bash
# 1. one-time: point the profile at your MFA device
#    (device ARN: AWS console → IAM → your user → Security credentials;
#     looks like arn:aws:iam::<account-id>:mfa/<device-name>)
aws configure set mfa_serial arn:aws:iam::<account-id>:mfa/<device-name> --profile <name>

# 2. each session: prompts for your 6-digit TOTP code
node dist/core/server.js login --profile <name> --duration-hours 8

# 3. verify — these succeed because the session was minted WITH MFA,
#    so the policy's explicit deny lifts
aws sts get-caller-identity --profile copilot-session
aws s3api list-buckets --profile copilot-session --query 'Buckets[0].Name'
```

Then point the server at the session profile
(`DEVOPS_COPILOT_PROFILES=copilot-session` in the client `env` block).
When credentials expire, tool errors tell you exactly which command to rerun.

## Testing with MCP Inspector

Poke any tool by hand from a browser UI. Note the `-e` flags — the Inspector
does **not** forward your shell environment to the spawned server:

```bash
npx @modelcontextprotocol/inspector \
  -e DEVOPS_COPILOT_PROFILES=<profile> \
  -e AWS_REGION=ap-south-1 \
  node dist/core/server.js
```

After connecting, call `list_accounts` first to confirm the server sees only
the profile you intended.

## Development

```bash
npm run dev    # tsc --watch
npm test       # vitest
```
