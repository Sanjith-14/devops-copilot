---
name: list_listeners
service: elastic-load-balancing-v2
operation: DescribeListeners
params:
  loadBalancerArn: { type: string, mapsTo: LoadBalancerArn, description: "ARN from elb_list_load_balancers" }
output: >-
  Listeners[].{arn: ListenerArn, port: Port, protocol: Protocol, sslPolicy: SslPolicy,
  certificates: Certificates[].CertificateArn,
  defaultActions: DefaultActions[].{type: Type, targetGroup: TargetGroupArn,
  redirect: RedirectConfig, fixedResponse: FixedResponseConfig.StatusCode}}
---
List the listeners (ports/protocols) of one load balancer, with TLS certificates and the
default action of each.
