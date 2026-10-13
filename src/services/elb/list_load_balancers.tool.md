---
name: list_load_balancers
service: elastic-load-balancing-v2
operation: DescribeLoadBalancers
params:
  names: { type: "string[]", optional: true, mapsTo: Names, description: "Only these load balancer names" }
fixed: { PageSize: 400 }
output: >-
  LoadBalancers[].{name: LoadBalancerName, arn: LoadBalancerArn, type: Type, scheme: Scheme,
  state: State.Code, dns: DNSName, vpcId: VpcId, azs: AvailabilityZones[].ZoneName,
  securityGroups: SecurityGroups, created: CreatedTime}
---
List Application/Network load balancers: type, internet-facing vs internal, state, DNS name,
VPC, AZs and security groups. For the full listener -> rule -> target map of one load
balancer, use elb_map_load_balancer.
