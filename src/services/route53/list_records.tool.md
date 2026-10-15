---
name: list_records
service: route-53
operation: ListResourceRecordSets
params:
  hostedZoneId: { type: string, mapsTo: HostedZoneId, description: "Zone id from route53_list_hosted_zones, e.g. /hostedzone/Z123" }
  startName: { type: string, optional: true, mapsTo: StartRecordName, description: "Start listing at this record name" }
fixed: { MaxItems: 300 }
output: >-
  ResourceRecordSets[].{name: Name, type: Type, ttl: TTL, values: ResourceRecords[].Value,
  aliasTo: AliasTarget.DNSName, routing: SetIdentifier, weight: Weight, region: Region,
  healthCheck: HealthCheckId}
---
List DNS records in a hosted zone: type, TTL, values, alias targets and routing policy
(weighted / latency / failover set identifiers). To follow a domain all the way to its
servers, use route53_trace_domain.
