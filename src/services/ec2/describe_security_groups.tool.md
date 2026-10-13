---
name: describe_security_groups
service: ec2
operation: DescribeSecurityGroups
params:
  groupIds: { type: "string[]", optional: true, mapsTo: GroupIds }
  vpcId: { type: string, optional: true, filter: vpc-id }
  name: { type: string, optional: true, filter: group-name, description: "Group name; * wildcards allowed" }
output: >-
  SecurityGroups[].{id: GroupId, name: GroupName, vpcId: VpcId, description: Description,
  inbound: IpPermissions[].{protocol: IpProtocol, fromPort: FromPort, toPort: ToPort,
  cidrs: IpRanges[].CidrIp, ipv6: Ipv6Ranges[].CidrIpv6, fromGroups: UserIdGroupPairs[].GroupId,
  prefixLists: PrefixListIds[].PrefixListId},
  outbound: IpPermissionsEgress[].{protocol: IpProtocol, fromPort: FromPort, toPort: ToPort,
  cidrs: IpRanges[].CidrIp, ipv6: Ipv6Ranges[].CidrIpv6, toGroups: UserIdGroupPairs[].GroupId}}
---
Show security groups with inbound and outbound rules. Protocol "-1" means all traffic;
fromGroups/toGroups are other security groups allowed as source/destination. To find rules
open to the whole internet, use ec2_find_open_security_groups.
