---
name: list_vpc_endpoints
service: ec2
operation: DescribeVpcEndpoints
params:
  vpcId: { type: string, optional: true, filter: vpc-id }
output: >-
  VpcEndpoints[].{id: VpcEndpointId, service: ServiceName, type: VpcEndpointType, state: State,
  vpcId: VpcId, routeTables: RouteTableIds, subnets: SubnetIds, privateDns: PrivateDnsEnabled}
---
List VPC endpoints (private connections to AWS services like S3, DynamoDB, ECR without going
through the internet): service name, Gateway vs Interface type, state, route tables and subnets.
