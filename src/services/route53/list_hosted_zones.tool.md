---
name: list_hosted_zones
service: route-53
operation: ListHostedZones
params: {}
output: >-
  HostedZones[].{id: Id, name: Name, private: Config.PrivateZone, records: ResourceRecordSetCount,
  comment: Config.Comment}
---
List Route 53 hosted zones (DNS domains) with public/private flag and record counts.
