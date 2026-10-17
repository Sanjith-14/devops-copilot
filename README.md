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
- **Service modules** (all read-only):
  | Module | Highlights |
  | --- | --- |
  | `s3` | buckets, public-access + encryption checks, objects |
  | `ec2` | instances, VPCs, subnets, route tables, NAT gateways, VPC endpoints, security groups, **`trace_instance_network`** (VPC → subnet → route → gateway → SGs → LBs → internet-exposure verdict), **`find_open_security_groups`** |
  | `elb` | load balancers, listeners, target groups, target health, **`map_load_balancer`** (listener → rule → target group → targets), **`find_load_balancers_for_target`** |
  | `cloudtrail` | **`recent_changes`** (who changed what, when, from which IP), **`resource_history`** (every change to one resource) |
  | `security` | **`scorecard`** — one-call posture report over IAM, S3, security groups, RDS, Secrets Manager: score, grade, ranked findings |
  | `route53`, `acm` | hosted zones, records, **`trace_domain`** (domain → DNS → load balancer → targets + TLS cert expiry), **`expiring_certificates`** |
  | `cost` | daily spend, spend spikes, anomalies, **`find_waste`** (unattached volumes, idle IPs, old snapshots, idle RDS, empty LBs, unused Lambdas — with $/month) |
  | `tagging` | cross-service inventory, **`find_untagged`** (tag compliance by resource type) |
  | `ecs`, `eks` | clusters, **`service_health`** (desired vs running, rollouts, *why tasks stopped*), EKS version/endpoint exposure/logging |
  | `iam`, `secrets` | users, roles; secret metadata + rotation status (values are never read) |
  | `rds`, `dynamodb`, `lambda` | inventory, config, health metrics, throttles/errors |
  | `cloudwatch`, `monitor`, `asg` | alarms, metrics, logs, scaling groups |
  | `aws` | **`aws_read`** — generic read-only call to *any* AWS API (see below) |
- **Core tools** — `list_accounts`, `list_modules`, `health_check`,
  `switch_account`, `run_across_accounts` (one read tool → many accounts in
  parallel, partial results), `list_assumable_roles`, and `assume_role`
  (ad-hoc role by ARN). See *Credentials & login* for roles + MFA.
- **Prompts** — ready-made workflows in the client's prompt menu:
  `daily_health_report`, `incident_triage`, `security_review`, `cost_review`.
- **Hardening** — every tool call is time-limited and writes one JSON audit
  line to stderr (`{"audit":"tool_call","tool":…,"account":…,"outcome":…}`,
  argument *names* only).

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
| `DEVOPS_COPILOT_TIMEOUT_MS` | `30000` | Per-tool-call timeout (time spent typing an MFA code isn't counted) |
| `AWS_REGION` | `us-east-1` | Fallback region when a profile has none |

## Credentials & login

The server never handles passwords — it uses whatever is in `~/.aws`, and
reloads it automatically when it changes. Run `npm link` once to get the
short **`awscm`** command (until then, `node dist/core/server.js` works in its
place); `awscm help` lists everything.

| You have | Do this |
| --- | --- |
| Access keys | `aws configure --profile <name>` — done |
| SSO | `aws sso login --profile <name>` |
| Keys + MFA policy | `awscm login` |
| Roles to assume | `awscm role add` once, then `role use` to switch |

### Roles (with or without MFA)

```bash
# once per role — finds your MFA device and saves a normal AWS CLI profile
awscm role add prod-ro arn:aws:iam::123456789012:role/ReadOnly --profile <your-profile>

# switch any time
awscm role use prod-ro      # asks for the 6-digit code only if needed
awscm role use staging-ro   # same day: no code — the MFA session is reused for 12h
awscm role list             # roles, which one is active (*), session status
```

The copilot always sees the active role (profile `copilot-active`), so
`role use` in a terminal switches it on the next request — no restart. In
chat you can also say *"switch to prod-ro"* (`switch_account`); if a code is
needed, the client shows a prompt, and the code goes to the server only,
never into the AI conversation. Saved roles work with the plain AWS CLI too:
`aws s3 ls --profile prod-ro`.

Don't know the role ARN? Ask *"which roles can I assume?"*
(`list_assumable_roles`): it lists roles in `~/.aws/config` and roles in your
account that trust you, flagging MFA / ExternalId requirements.

### MFA session without roles

For IAM users whose policy denies everything until MFA is used:

```bash
awscm login --profile <your-profile>   # 6-digit code -> 12h session (profile copilot-session)
```

The MFA device is detected automatically (set `mfa_serial` on the profile
to pin it). `role use` reuses this session, so after `login` switching
roles needs no code at all.

<details><summary>How it works</summary>

1. `GetCallerIdentity` → your IAM user; IAM `ListMFADevices` on yourself → MFA device.
2. Try the role without MFA; only if AWS says no, ask for the code.
3. `GetSessionToken(device, code)` → a 12h MFA session (cached in `copilot-session`),
   then `AssumeRole` from that session. This also works under "deny everything
   without MFA" policies, and lets roles refresh without new codes.
</details>

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

## Adding tools — three tiers

**1. Nothing at all: `aws_read`.** The LLM already knows the AWS APIs, so for
services without a module it calls e.g.
`aws_read({ service: "ecs", operation: "DescribeClusters", params: {...}, output: "clusters[].clusterName" })`.
Code — not the model — enforces the safety rules:
only `Describe*/List*/Get*/Search*/Lookup*` operations run; secret-returning
ones (`GetSecretValue`, `GetParameter`, `GetPasswordData`, …) are blocked;
password/secret/token fields and env-var values are redacted; responses are
size-capped. The service needs its SDK package installed
(`npm install @aws-sdk/client-<service>`).

**2. A markdown file: one API call → one named tool.** Drop
`src/services/<module>/<tool>.tool.md` in a folder; the registry turns it into
a tool at startup (`npm run build` copies it to `dist/`):

```md
---
name: list_vpcs
service: ec2                  # @aws-sdk/client-ec2
operation: DescribeVpcs       # DescribeVpcsCommand
params:
  vpcIds: { type: "string[]", optional: true, mapsTo: VpcIds }
  state:  { type: string, optional: true, filter: state }   # EC2-style Filters
fixed: { MaxResults: 100 }     # constant request fields
output: "Vpcs[].{id: VpcId, cidr: CidrBlock}"   # JMESPath projection
---
List VPCs with their CIDR ranges.   <- the description the LLM reads
```

Param types: `string`, `number`, `boolean`, `string[]` (+ `enum`, `description`).
A file that labels a write operation `read` is rejected at startup. A folder
with only `.tool.md` files (plus an optional `module.md` with a `health:`
operation) becomes a module with zero TypeScript.

**3. TypeScript: multi-step logic.** When a tool chains several calls or
computes a verdict (`ec2_trace_instance_network`, `elb_map_load_balancer`),
write it in the module's `tools.ts` — see existing modules. Markdown and
TypeScript tools can live side by side in the same folder.

## IAM permissions

Every tool is read-only. Grant the AWS-managed `ReadOnlyAccess` policy, or at
least the `Describe*/List*/Get*` actions for the services you use:

| Feature | Actions |
| --- | --- |
| network tools | `ec2:Describe*`, `elasticloadbalancing:Describe*` |
| what changed | `cloudtrail:LookupEvents` |
| security scorecard | `iam:ListUsers`, `iam:GetLoginProfile`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccountSummary`, `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `ec2:DescribeSecurityGroups`, `rds:DescribeDBInstances`, `secretsmanager:ListSecrets` |
| domain trace / certs | `route53:ListHostedZones`, `route53:ListResourceRecordSets`, `acm:ListCertificates` |
| waste finder | `ec2:DescribeVolumes/Addresses/Snapshots`, `cloudwatch:GetMetricStatistics`, `rds:Describe*`, `lambda:ListFunctions` |
| tags, containers | `tag:GetResources`, `ecs:List*/Describe*`, `eks:List*/Describe*` |
| roles | `sts:AssumeRole` on the role, `sts:GetSessionToken`, `iam:ListMFADevices` on yourself, `iam:ListRoles` (discovery only) |

A denied call returns the AWS error to the LLM; composite tools (scorecard,
waste finder, traces) return partial results and mark the denied sections as
`skipped` instead of failing.

## Development

```bash
npm run dev    # tsc --watch (re-run `npm run build` after editing .tool.md files)
npm test       # vitest
```
