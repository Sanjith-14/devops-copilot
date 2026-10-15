---
name: list_nodegroups
service: eks
operation: ListNodegroups
params:
  clusterName: { type: string, description: "Cluster name" }
fixed: { maxResults: 100 }
output: "nodegroups"
---
List managed node group names of an EKS cluster.
