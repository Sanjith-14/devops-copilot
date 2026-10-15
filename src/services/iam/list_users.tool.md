---
name: list_users
service: iam
operation: ListUsers
params:
  pathPrefix: { type: string, optional: true, mapsTo: PathPrefix, description: "Only users under this path, e.g. /admins/" }
fixed: { MaxItems: 1000 }
output: >-
  Users[].{name: UserName, arn: Arn, created: CreateDate, passwordLastUsed: PasswordLastUsed}
---
List IAM users with creation date and when their console password was last used (empty =
never used or no console access).
