---
name: list_nat_gateways
service: ec2
operation: DescribeNatGateways
params:
  vpcId: { type: string, optional: true, filter: vpc-id }
output: >-
  NatGateways[].{id: NatGatewayId, name: Tags[?Key=='Name'].Value | [0], state: State, vpcId: VpcId,
  subnetId: SubnetId, connectivity: ConnectivityType, publicIps: NatGatewayAddresses[].PublicIp,
  privateIps: NatGatewayAddresses[].PrivateIp, failure: FailureMessage}
---
List NAT gateways: state, VPC, the (public) subnet each lives in, and its public/private IPs.
Private subnets reach the internet through these.
