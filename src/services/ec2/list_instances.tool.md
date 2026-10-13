---
name: list_instances
service: ec2
operation: DescribeInstances
params:
  instanceIds: { type: "string[]", optional: true, mapsTo: InstanceIds, description: "Only these instance ids" }
  state:
    type: string
    optional: true
    filter: instance-state-name
    enum: [pending, running, stopping, stopped, shutting-down, terminated]
  vpcId: { type: string, optional: true, filter: vpc-id, description: "Only instances in this VPC" }
  name: { type: string, optional: true, filter: "tag:Name", description: "Name tag; supports * wildcards, e.g. 'api-*'" }
output: >-
  Reservations[].Instances[].{id: InstanceId, name: Tags[?Key=='Name'].Value | [0], type: InstanceType,
  state: State.Name, privateIp: PrivateIpAddress, publicIp: PublicIpAddress, vpcId: VpcId,
  subnetId: SubnetId, az: Placement.AvailabilityZone, securityGroups: SecurityGroups[].GroupId,
  launched: LaunchTime}
---
List EC2 instances with Name tag, type, state, private/public IP, VPC, subnet, AZ and security
groups. Filter by state, VPC, or Name tag (wildcards allowed). For how one instance reaches the
internet, use ec2_trace_instance_network.
