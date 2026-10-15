---
name: list_secrets
service: secrets-manager
operation: ListSecrets
fixed: { MaxResults: 100 }
output: >-
  SecretList[].{name: Name, description: Description, rotationEnabled: RotationEnabled || `false`,
  lastRotated: LastRotatedDate, nextRotation: NextRotationDate, lastChanged: LastChangedDate,
  lastAccessed: LastAccessedDate, created: CreatedDate, customKms: KmsKeyId != null}
---
List Secrets Manager secrets with rotation status (enabled, last/next rotation), last change and
last access dates — metadata only, secret values are never read. A secret not accessed in
months may be unused; one with rotation disabled is a hygiene finding.
