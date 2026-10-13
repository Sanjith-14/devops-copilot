---
name: describe_route_tables
service: ec2
operation: DescribeRouteTables
params:
  vpcId: { type: string, optional: true, filter: vpc-id, description: "All route tables in this VPC" }
  subnetId:
    type: string
    optional: true
    filter: association.subnet-id
    description: "Route table EXPLICITLY associated with this subnet (none = the subnet uses the VPC's main table)"
  routeTableIds: { type: "string[]", optional: true, mapsTo: RouteTableIds }
output: >-
  RouteTables[].{id: RouteTableId, name: Tags[?Key=='Name'].Value | [0], vpcId: VpcId,
  main: length(Associations[?Main]) > `0`, subnets: Associations[].SubnetId,
  routes: Routes[].{destination: DestinationCidrBlock || DestinationIpv6CidrBlock || DestinationPrefixListId,
  target: GatewayId || NatGatewayId || TransitGatewayId || VpcPeeringConnectionId || NetworkInterfaceId
  || InstanceId || VpcEndpointId || LocalGatewayId || CarrierGatewayId, state: State}}
---
Show route tables with their routes and associated subnets. The route target prefix says where
traffic goes: igw-* internet gateway, nat-* NAT gateway, tgw-* transit gateway, pcx-* VPC
peering, vpce-* VPC endpoint, eni-* network interface, "local" = inside the VPC. A state of
"blackhole" means the target no longer exists. Subnets without an explicit association use the
table marked main=true.
