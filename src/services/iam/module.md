---
health: { service: iam, operation: ListUsers, params: { MaxItems: 1 } }
---
AWS IAM inventory (read-only): users and roles. For security findings use security_scorecard; for roles you can assume use list_assumable_roles.
