---
name: list_target_groups
service: elastic-load-balancing-v2
operation: DescribeTargetGroups
params:
  loadBalancerArn: { type: string, optional: true, mapsTo: LoadBalancerArn, description: "Only groups used by this LB" }
  names: { type: "string[]", optional: true, mapsTo: Names }
fixed: { PageSize: 400 }
output: >-
  TargetGroups[].{name: TargetGroupName, arn: TargetGroupArn, protocol: Protocol, port: Port,
  targetType: TargetType, vpcId: VpcId, loadBalancers: LoadBalancerArns,
  healthCheck: {protocol: HealthCheckProtocol, port: HealthCheckPort, path: HealthCheckPath,
  healthyThreshold: HealthyThresholdCount, unhealthyThreshold: UnhealthyThresholdCount}}
---
List target groups: protocol/port, target type (instance, ip, lambda, alb), VPC, health check
settings, and which load balancers use them.
