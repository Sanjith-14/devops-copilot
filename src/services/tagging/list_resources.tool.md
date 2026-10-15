---
name: list_resources
service: resource-groups-tagging-api
operation: GetResources
params:
  resourceTypes:
    type: "string[]"
    optional: true
    mapsTo: ResourceTypeFilters
    description: "e.g. ['ec2:instance', 's3', 'rds:db', 'lambda:function']"
fixed: { ResourcesPerPage: 100 }
output: >-
  ResourceTagMappingList[].{arn: ResourceARN, tags: Tags}
---
Inventory of tagged resources across services in one region (ARN + tags), optionally filtered
by resource type. For missing-tag audits use tagging_find_untagged.
