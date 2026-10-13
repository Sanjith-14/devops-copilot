---
name: list_subnets
service: ec2
operation: DescribeSubnets
params:
  vpcId: { type: string, optional: true, filter: vpc-id, description: "Only subnets in this VPC" }
  subnetIds: { type: "string[]", optional: true, mapsTo: SubnetIds }
output: >-
  Subnets[].{id: SubnetId, name: Tags[?Key=='Name'].Value | [0], vpcId: VpcId, cidr: CidrBlock,
  az: AvailabilityZone, freeIps: AvailableIpAddressCount, autoAssignPublicIp: MapPublicIpOnLaunch,
  defaultForAz: DefaultForAz}
---
List subnets with CIDR, AZ, free IP count and whether instances get a public IP automatically.
Note: a subnet is truly "public" only if its route table sends 0.0.0.0/0 to an internet gateway
(igw-*) — check with ec2_describe_route_tables.
