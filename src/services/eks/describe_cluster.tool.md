---
name: describe_cluster
service: eks
operation: DescribeCluster
params:
  name: { type: string, description: "Cluster name from eks_list_clusters" }
output: >-
  cluster.{name: name, status: status, version: version, platformVersion: platformVersion,
  endpoint: endpoint, publicEndpoint: resourcesVpcConfig.endpointPublicAccess,
  publicAccessCidrs: resourcesVpcConfig.publicAccessCidrs,
  privateEndpoint: resourcesVpcConfig.endpointPrivateAccess, vpcId: resourcesVpcConfig.vpcId,
  subnets: resourcesVpcConfig.subnetIds, securityGroups: resourcesVpcConfig.securityGroupIds,
  logging: logging.clusterLogging[?enabled].types[], created: createdAt,
  health: health.issues}
---
Details of one EKS cluster: Kubernetes version and status, whether the API endpoint is public
(and from which CIDRs — 0.0.0.0/0 is a security finding), VPC/subnets/security groups, which
control-plane log types are enabled, and AWS-reported health issues.
