---
name: list_vpcs
service: ec2
operation: DescribeVpcs
params:
  vpcIds: { type: "string[]", optional: true, mapsTo: VpcIds, description: "Only these VPC ids" }
output: >-
  Vpcs[].{id: VpcId, name: Tags[?Key=='Name'].Value | [0], cidr: CidrBlock,
  allCidrs: CidrBlockAssociationSet[].CidrBlock, isDefault: IsDefault, state: State}
---
List VPCs with Name tag, primary and secondary CIDR blocks, and whether each is the account's
default VPC.
