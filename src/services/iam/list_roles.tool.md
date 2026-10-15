---
name: list_roles
service: iam
operation: ListRoles
params:
  pathPrefix: { type: string, optional: true, mapsTo: PathPrefix, description: "e.g. /service-role/" }
fixed: { MaxItems: 1000 }
output: >-
  Roles[].{name: RoleName, arn: Arn, created: CreateDate, description: Description,
  maxSessionHours: MaxSessionDuration}
---
List IAM roles in the account with description and maximum session duration (seconds).
