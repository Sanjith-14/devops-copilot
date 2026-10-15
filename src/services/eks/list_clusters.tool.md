---
name: list_clusters
service: eks
operation: ListClusters
fixed: { maxResults: 100 }
output: "clusters"
---
List EKS (Kubernetes) cluster names in the region. Use eks_describe_cluster for details.
