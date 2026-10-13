---
name: get_target_health
service: elastic-load-balancing-v2
operation: DescribeTargetHealth
params:
  targetGroupArn: { type: string, mapsTo: TargetGroupArn, description: "ARN from elb_list_target_groups" }
output: >-
  TargetHealthDescriptions[].{target: Target.Id, port: Target.Port, az: Target.AvailabilityZone,
  state: TargetHealth.State, reason: TargetHealth.Reason, detail: TargetHealth.Description}
---
Show every target (instance id or IP) registered in a target group with its health state
(healthy, unhealthy, draining, unused, initial) and the reason when it isn't healthy.
