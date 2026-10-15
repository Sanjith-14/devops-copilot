---
name: list_certificates
service: acm
operation: ListCertificates
params:
  statuses:
    type: "string[]"
    optional: true
    mapsTo: CertificateStatuses
    description: "e.g. ISSUED, PENDING_VALIDATION, EXPIRED"
fixed:
  MaxItems: 1000
  Includes: { keyTypes: [RSA_1024, RSA_2048, RSA_3072, RSA_4096, EC_prime256v1, EC_secp384r1, EC_secp521r1] }
output: >-
  CertificateSummaryList[].{domain: DomainName, arn: CertificateArn, status: Status, type: Type,
  inUse: InUse, expires: NotAfter, renewal: RenewalEligibility,
  altNames: SubjectAlternativeNameSummaries}
---
List ACM TLS certificates: domain, status, AMAZON_ISSUED vs IMPORTED, whether in use, expiry
date and renewal eligibility. CloudFront certificates live in us-east-1 (pass region).
