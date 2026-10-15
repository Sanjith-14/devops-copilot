---
health: { service: secrets-manager, operation: ListSecrets, params: { MaxResults: 1 } }
---
AWS Secrets Manager metadata (read-only): secret names, rotation status and access dates. Secret VALUES are never read.
