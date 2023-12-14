# Amazon ECS Service Connect Agent

![Amazon ECS logo](doc/ecs.png "Amazon AWS ECS")

The Amazon ECS Service Connect Agent is a primary component of [Amazon ECS Service Connect](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-connect.html) and [AWS App Mesh](https://aws.amazon.com/app-mesh/). It monitors the Envoy proxy and provides a management interface. This management interface serves as a safe endpoint to interact with the Envoy proxy and provides several APIs for health checks, telemetry data and summarizes the operating condition of the proxy. It is used in both ECS Service Connect proxy and App Mesh [Envoy Docker Image](https://docs.aws.amazon.com/app-mesh/latest/userguide/envoy.html).


## Building the Agent

On an [Amazon Linux AMI](https://aws.amazon.com/amazon-linux-ami/). Download Go at https://go.dev/doc/install. In the project's `agent` directory, issue the `make` command to compile the agent binary:

```
$ yum -y install docker
$ yum -y groupinstall "Development Tools"
$ make
go fmt ./...
go test -mod=vendor -count=1 -v ./...
...
$ ls -laF agent
-rwxrwxr-x 1 ec2-user ec2-user 21192704 Feb  1 18:40 agent*
```


To create an Envoy image, you could use the following example files:

Example `Dockerfile.agent`:

```
COPY agent /usr/bin/agent

CMD /usr/bin/agent
```

Example `Makefile`:

```
AWS_REGION ?= us-west-2
SSM_PARAMETER = "/aws/service/appmesh/envoy"
IMAGE_STRING = $(shell aws --region $(AWS_REGION) ssm get-parameter --name $(SSM_PARAMETER) --query Parameter.Value)
ECR = $(shell echo $(IMAGE_STRING) | cut -d / -f 1)
IMAGE_NAME ?= "ecs-service-connect-agent:latest"

.PHONY: docker-build
docker-build:
        ECR=$(shell echo $(IMAGE_STRING) | sed 's/\(.*\):\(.*\)/\1/g')
        echo "FROM $(IMAGE_STRING)" > source
        cat source Dockerfile.agent > Dockerfile

        aws ecr get-login-password | docker login --password-stdin --username AWS $(ECR)
        docker build -t $(IMAGE_NAME) .
        rm source Dockerfile
```

Place these files along with the built `agent` binary in a single directory and issue the `make docker-build` command. The resulting `ecs-service-connect:latest` can be used in ECS Service Connect or App Mesh as a sidecar.

## Advanced Usage

The Amazon ECS Service Connect Agent supports using a few environment variables to alter some aspects of the Envoy's behavior. These variables are outlined below, and documented in the AWS App Mesh [User Guide](https://docs.aws.amazon.com/app-mesh/latest/userguide/envoy-config.html). These environment variables can be configured when used with AWS App Mesh, and they are not configurable when used with ECS Service Connect.




**Required Variables**

|Environment Key	|Example Value(s)	|Description	|Default Value	|
|---	|---	|---	|---	|
|`APPMESH_RESOURCE_ARN`	|	|When you add the Envoy container to a task group, set this environment variable to the ARN of the virtual node or the virtual gateway that the task group represents	|	|


**Envoy Bootstrap Environment Variables**

These environment variables offer controls for the bootstrap config generation for Envoy when it's started.

|Environment Key	|Example Value(s)	|Description	|Default Value	|
|---	|---	|---	|---	|
|`ENVOY_ADMIN_MODE`	| <tcp &#124; uds>	| Specify whether to bind Envoy's admin interface to a tcp address or a unix socket.	| tcp	|
|`ENVOY_ADMIN_ACCESS_LOG_FILE`	|/path/to/access.log	|Log file for the Envoy admin access service	|/var/log/envoy_admin_access.log	|
|`ENVOY_ADMIN_ACCESS_PORT`	|1234	|Port where Envoy admin access is reachable and also to override the default port through which Amazon ECS Service Connect Agent is connecting to envoy 	|9901	|
|`ENVOY_ADMIN_ACCESS_ENABLE_IPV6`	|<true &#124; false>	|Determines if the Envoy will listen for IPv6 traffic on the admin interface 	|false	|
|`ENVOY_LOG_LEVEL`	|<info &#124; warn &#124; error &#124; debug &#124; trace>	|Envoy Log Level	|info	|
|`ENVOY_INITIAL_FETCH_TIMEOUT`	|	|Length of time Envoy will wait for an initial config response	|0	|
|`ENVOY_CONCURRENCY`  | 2 | number of concurrent processes for Envoy |-1 |
|`ENABLE_ENVOY_STATS_TAGS`	|<0 &#124; 1>	|Enables the use of App Mesh defined tags `appmesh.mesh` and `appmesh.virtual_node`. For more information, see [config.metrics.v3.TagSpecifier](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#config-metrics-v3-tagspecifier) in the Envoy documentation. To enable, set the value to 1. |   |
|`ENVOY_STATS_FLUSH_INTERVAL`  | 5000ms | Sets optional duration between flushes to configured stats sinks. (unit: Duration) | 5000ms |
|`ENVOY_STATS_CONFIG_FILE`	|	|Stats config file (see: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/observability/statistics).	|	|
|`ENVOY_STATS_SINKS_CFG_FILE`	|	|Specify a file path in the Envoy container file system to override the default configuration with your own. For more information, see [config.metrics.v3.StatsSink](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/metrics/v3/stats.proto#config-metrics-v3-statssink) in the Envoy documentation.	|	|
|`ENABLE_ENVOY_DOG_STATSD`	|<0 &#124; 1>	|Enables DogStatsD stats using `127.0.0.1:8125` as the default daemon endpoint	|0	|
|`STATSD_PORT`	|1234	|Specify a port value to override the default DogStatsD daemon port	|8125	|
|`STATSD_ADDRESS`	|127.0.0.1	|Specify an IP address value to override the default DogStatsD daemon IP address.  This variable can only be used with version `1.15.0` or later of the Envoy image.	|127.0.0.1	|
|`STATSD_SOCKET_PATH`	|/path/to/socket	|Specify a unix domain socket for the DogStatsD daemon. If this variable is not specified, and if DogStatsD is enabled, then this value defaults to the DogStatsD daemon IP address port of `127.0.0.1:8125`. If the `ENVOY_STATS_SINKS_CFG_FILE` variable is specified containing a stats sinks configuration, it will override all of the DogStatsD variables. This variable is supported with Envoy image version `v1.19.1.0-prod` or late	|	|
|`APPMESH_METRIC_EXTENSION_VERSION`	|<0 &#124; 1>	|Enables the App Mesh metrics extension	|	|
|`ENABLE_ENVOY_XRAY_TRACING`	|<0 &#124; 1>	|Enables X-Ray tracing using 127.0.0.1:2000 as the default daemon endpoint	|	|
|`XRAY_DAEMON_PORT`	|1234	|Overrides the X-Ray daemon port	|2000	|
|`XRAY_SAMPLING_RATE`	|0.0 - 1.00	|Override the default sampling rate of 0.05 (5%) for AWS X-Ray tracer. The value should be specified as a decimal between 0 and 1.00 (100%). This will be overridden if `XRAY_SAMPLING_RULE_MANIFEST` is specified	|	|
|`XRAY_SAMPLING_RULE_MANIFEST`	|/path/to/ruleset	|Specify a file path in the Envoy container file system to configure the localized custom sampling rules for the X-Ray tracer. For more information, see [Sampling rules](https://docs.aws.amazon.com/xray/latest/devguide/xray-sdk-go-configuration.html#xray-sdk-go-configuration-sampling) in the *AWS X-Ray Developer Guide*	|	|
|`XRAY_SEGMENT_NAME`	|“mesh/resourceName”	|Specify a segment name for traces to override the default X-Ray segment name. This variable is supported with Envoy image version `v1.23.0.0-prod` or later.	|`meshName`/`virtualNodeName`	|
|`AWS_XRAY_DAEMON_ADDRESS`  | **Same port** – `address:port`; **Different ports** – `tcp:address:port udp:address:port` | Set the host and port of the X-Ray daemon listener. Use this variable if you have configured the daemon to [listen on a different port](https://docs.aws.amazon.com/xray/latest/devguide/xray-daemon-configuration.html) or if it is running on a different host. | By default, the SDK uses `127.0.0.1:2000` for both trace data (UDP) and sampling (TCP) |
|`ENABLE_ENVOY_DATADOG_TRACING`	|<0 &#124; 1>	|Enables Datadog trace collection using `127.0.0.1:8126` as the default Datadog agent endpoint. To enable, set the value to `1`	|0	|
|`DATADOG_TRACER_PORT`	|1234	|Specify a port value to override the default Datadog agent port	|8126	|
|`DATADOG_TRACER_ADDRESS`	|127.0.0.1	|Specify an IP address to override the default Datadog agent address	|127.0.0.1	|
|`DD_SERVICE`	|“mesh/resourceName”	|Specify a service name for traces to override the default Datadog service name. This variable is supported with Envoy image version `v1.18.3.0-prod` or later.	|`envoy-meshName`/`virtualNodeName`	|
|`ENABLE_ENVOY_JAEGER_TRACING`	|<0 &#124; 1>	|Enables Jaeger trace collection using `127.0.0.1:9411` as the default Jaeger endpoint	|0	|
|`JAEGER_TRACER_PORT`	|1234	|Specify a port value to override the default Jaeger port	|9411	|
|`JAEGER_TRACER_ADDRESS`	|127.0.0.1	|Specify an IP address to override the default Jaeger address	|127.0.0.1	|
|`JAEGER_TRACER_VERSION`	|<PROTO &#124; JSON>	|Specify whether the collector needs traces in `JSON` or `PROTO` endoded format	|PROTO	|
|`ENVOY_TRACING_CFG_FILE`	|	|Tracing configuration file (see: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/observability/tracing).	|	|
|`ENVOY_CONFIG_FILE`	|/usr/local/etc/envoy.yaml	|Location of an alternative Envoy configuration file. If it is provided, a full and valid config file must be provided to the container. If this is not provided the Agent generates the config file.	|	|
|`ENVOY_RESOURCES_CONFIG_FILE`	|/usr/local/etc/resources.yaml	|Location for providing additional resources to be applied on the bootstrap configuration file.  If this is specified the Agent will concatenate the resources with the default resources that are generated.	|	|
|`APPMESH_RESOURCE_CLUSTER`	|	|By default App Mesh uses the name of the resource you specified in `APPMESH_RESOURCE_ARN` when Envoy is referring to itself in metrics and traces. You can override this behavior by setting the `APPMESH_RESOURCE_CLUSTER` environment variable with your own name. This variable can only be used with version `1.15.0` or later of the Envoy image.	|	|
|`APPMESH_XDS_ENDPOINT`	|hostname.aws:1234	|Envoy's configuration endpoint with port	| `appmesh-envoy-management.$AWS_REGION.amazonaws.com:443`	|
|`APPMESH_SIGNING_NAME`  | appmesh | The service signing name for Aws request signing filter. | appmesh |
|`APPMESH_SET_TRACING_DECISION`	|<true &#124; false>	|Controls whether Envoy modifies the `x-request-id` header appearing in a request from a client	|TRUE	|
|`ENVOY_NO_EXTENSION_LOOKUP_BY_NAME`	|<true &#124; false>	|Controls whether Envoy needs type URL to lookup extensions regardless of the name field. If the type URL is missing it will reject (NACK) the configuration	|true	|
|`ENVOY_ENABLE_TCP_POOL_IDLE_TIMEOUT`	|<true &#124; false>	|Controls whether the `idle_timeout` protocol options feature is enabled for TCP upstreams. If not configured the default `idle_timeout` is 10 minutes. Set this environment variable to `false` to disable `idle_timeout` option.	|true	|
|`ENVOY_USE_HTTP_CLIENT_TO_FETCH_AWS_CREDENTIALS`	|<true &#124; false>	|Controls whether to use http async client to fetch AWS credentials in Envoy from metadata credentials providers instead of libcurl. The usage of libcurl is deprecated in Envoy	|false	|
|`MAX_REQUESTS_PER_IO_CYCLE`	|1	|For setting the limit on the number of HTTP requests processed from a single connection in a single I/O cycle. Requests over this limit are processed in subsequent I/O cycles. This mitigates CPU starvation by connections that simultaneously send high number of requests by allowing requests from other connections to make progress. This runtime value can be set to 1 in the presence of abusive HTTP/2 or HTTP/3 connections. By default this is not set.	|	|
|`APPMESH_SDS_SOCKET_PATH`	|/path/to/socket	|Unix Domain Socket for SDS Based TLS.	|	|
|`APPMESH_PREVIEW`	|<0 &#124; 1>	|Enables the App Mesh Preview Endpoint	|	|
|`APPMESH_DUALSTACK_ENDPOINT`	|<0 &#124; 1>	|Enables the App Mesh Dual-Stack Endpoint	|	|
|`APPMESH_PLATFORM_K8S_VERSION`	|“v1.21.2”	|For Envoy running on K8s, K8s platform version injected by App Mesh Controller	|	|
|`APPMESH_PLATFORM_APP_MESH_CONTROLLER_VERSION`	|"v1.4.1"	|For Envoy running on K8s, app mesh controller version injected by App Mesh Controller	|	|

**Agent Sidecar Operation Environment Variables**

These environment variables offer controls to alter Amazon ECS Service Connect Agent functionality acting as a process manager for Envoy and serving useful APIs via a management interface.

|Environment Key	|Example Value(s)	|Description	|Default Value	|
|---	|---	|---	|---	|
|`APPNET_ENVOY_RESTART_COUNT`	|10	|The number of times the Agent will restart Envoy within a running task	|0	|
|`PID_POLL_INTERVAL_MS`	|25	|The interval at which the Envoy process’ state is checked	|100	|
|`LISTENER_DRAIN_WAIT_TIME_S`	|1	|Controls the time Envoy waits for active connections to gracefully close before the process exits	|20	|
|`APPNET_AGENT_ADMIN_MODE`  | <tcp &#124; uds> | Starts Agent's management interface server and binds it to either a tcp address or a unix socket. |  |
|`APPNET_AGENT_HTTP_PORT`  |1234  |Specify a port to be used for binding Agent's management interface in tcp mode. Ensure port value is > 1024 if uid != 0.  Ensure port is less than 65535 | 9902  |
|`APPNET_AGENT_HTTP_BIND_ADDRESS` |127.0.0.1	|Specify an IP address to override the default Amazon ECS Service Connect Agent Management interface address in tcp mode.	|[::]	|
|`APPNET_AGENT_ADMIN_UDS_PATH` |/path/to/socket |Specify unix domain socket path for Amazon ECS Service Connect agent management interface in uds mode. |/var/run/ecs/appnet_admin.sock   |
|`APPNET_AGENT_LOGGING_RESET_TIMEOUT` |300 |Length of time agent will wait for log level to be reset after it is updated via `/enableLogging` endpoint (unit: s)  | 300  |
|`APPNET_ENVOY_LOG_DESTINATION` |stdout/stderr |Location of log file of the agent. If this variable is set to a file, the log won't be printed to stdour/stderr. If this variable is not set or is set to an empty string, the default value will be applied.   |stdout/stderr   |
|`APPNET_ENVOY_LOG_NAME` |appnet_envoy.log |The name of Log file of the agent  |appnet_envoy.log   |
|`APPNET_AGENT_MAX_LOG_FILE_SIZE` |1.0 |The max size of log file of the agent (unit: MB)  |1.0   |
|`APPNET_AGENT_MAX_RETENTION_COUNT` |3 |The max number of log files of the agent  |5   |
|`HC_POLL_INTERVAL_MS` |2000 |The interval at which the agent health checks envoy (unit: ms)  | 10000   |
|`HC_DISCONNECTED_TIMEOUT_S`  | 3600 | Timeout after which a continued disconnection from management server would result in failing orchestrator health checks (unit: s) | 604800 |
|`APPNET_AGENT_POLL_ENVOY_READINESS_INTERVAL_S` |5 | Specified by the controller when running on EKS, this specifies the interval of non-daemon envoy health checks by agent. (second) |5   |
|`APPNET_AGENT_POLL_ENVOY_READINESS_TIMEOUT_S` |180 |The timeout of non-daemon envoy health check (second) |180   |
|`ENABLE_STATS_SNAPSHOT`  | <true &#124; false> | Specify whether the agent should take periodic snapshot of emitted stats and compute a timed delta. | false |

**Agent Relay Mode Operation Environment Variables**

These environment variables offer controls to alter the agent functionality when running in the Relay mode. The relay runs one per container instance and proxies xDS connections/requests from all the Amazon ECS Service Connect Agent containers running on the host to the control plane management server. It uses a static bootstrap config file stored in `agent/resources/bootstrap_configs/relay_bootstrap.yaml` file.

|Environment Key	|Example Value(s)	|Description	|Default Value	|
|---	|---	|---	|---	|
|`APPNET_ENABLE_RELAY_MODE_FOR_XDS` |<0 &#124; 1> |Enables relay mode for the agent to be run on the container instance. If set as 1, Envoy would be bootstrapped with the static config present in the image and act as a relay for all communication between the agent containers on the instance and the management server. |0   |
|`APPNET_MANAGEMENT_DOMAIN_NAME` |hostname.aws.api | Management service endpoint domain name for relay bootstrap config generation. |ecs-sc.$AWS_REGION.aws.api  |
|`APPNET_MANAGEMENT_PORT` |1234 | Management service endpoint port for relay bootstrap config generation. |443  |
|`APPNET_RELAY_LISTENER_UDS_PATH` |/path/to/socket |Specify unix domain socket path for xDS Relay listener to serve control plane requests from the Amazon ECS Service Connect Agent. | `/tmp/relay_xds.sock` |
|`RELAY_STREAM_IDLE_TIMEOUT`  | 2000s | Timeout value for connection between the agent in relay mode and the management server. | 2400s |
|`RELAY_BUFFER_LIMIT_BYTES`  | 10485760 | Allows for configurable connection buffer limit for agent in relay mode. | 10485760 |


**Agent Local Relay Mode Operation Environment Variables**

These environment variables offer controls to alter the agent functionality when running in the Local Relay mode. The local relay envoy runs as a separate process inside the container and proxies xDS connections/requests from the AppMesh Envoy container to the control plane management server. It uses a static bootstrap config file stored in `agent/resources/bootstrap_configs/local_relay_bootstrap.yaml` file. Note that the local relay mode is only enabled for AppMesh mode and not enabled for Amazon ECS Service Connect mode.


|Environment Key	|Example Value(s)	|Description	|Default Value	|
|---	|---	|---	|---	|
|`APPNET_LOCAL_RELAY_LISTENER_PORT` |1234 |Specify the port on which the local relay Envoy will be listening to serve the xDS requests coming from Envoy process. |15003   |
|`APPNET_LOCAL_RELAY_ADMIN_PORT` |9905 | Specify the port on which the local relay Envoy admin access is reachable. Make sure this value if set doesn't conflict with the `ENVOY_ADMIN_ACCESS_PORT` |9903  |
|`APPNET_LOCAL_RELAY_ADMIN_HOST` |0.0.0.0 | Specify an IP address to override the default local relay Envoy management interface address. By default this admin interface will not be exposed outside the container. If you want to access this interface outside the container then set this value to `0.0.0.0` and make sure you don't allow free or public access to this endpoint |127.0.0.1  |
|`APPNET_LOCAL_RELAY_LOG_DESTINATION` |/dev |Location of local relay Envoy debug log folder. If you want the logs to be printed to stdour/stderr then set this value to `/dev`. If this variable is not set or is set to an empty string, the default logs will be stored inside `/tmp` folder. | `/tmp` |
|`APPNET_LOCAL_RELAY_LOG_FILE_NAME`  | stdout/stderr | Location of local relay Envoy debug log file. If you want the logs to be printed to stdour/stderr then set this value to `stdout` or `stderr`.| `local_relay_appnet_envoy.log` |


**Management Server Operating Environment Variables**

These environment variables are used to pass operating platform/environment information to the management server for control plane operations and dynamic configuration generation.

|Environment Key	|Example Value(s)	|Description	|Default Value	|
|---	|---	|---	|---	|
|`ECS_CONTAINER_INSTANCE_ARN`  | `arn:aws:ecs:region:aws_account_id:container-instance/cluster-name/container-instance-id` | When set, used to send ECS container instance Arn information to management server for authorization purposes. |  |
|`APPMESH_PLATFORM_K8S_POD_UID`  | `arn:aws:ecs:region:aws_account_id:container-instance/cluster-name/container-instance-id` | For Envoy running on K8s, Pod UID injected by App Mesh Controller. |  |
|`APPNET_CONTAINER_IP_MAPPING`  | `{"App1":"172.10.1.1","App2":"172.10.1.2"}` | Specifies address mapping of application container as set by ECS agent in ECS Service Connect. |  |
|`APPNET_LISTENER_PORT_MAPPING`  | `{"Listener1":15000,"Listener2":15001}` | Specifies port mapping for each application port as set by ECS agent in ECS Service Connect. |  |

### Deprecated

* `APPMESH_RESOURCE_NAME`
* `APPMESH_VIRTUAL_NODE_NAME`

### Management APIs

The Amazon ECS Service Connect Agent offers a local management interface when `APPNET_AGENT_ADMIN_MODE` is set. Following are the supported queries:

* `GET /status`: Returns Envoy operating information such as its connectivity state, restarts count, connection with control plane, health check, etc.
* `POST /drain_listeners`: Drains all inbound Envoy listeners.
* `POST /enableLogging?level=<desired_level>`: Change Envoy logging level across all loggers. The change is automatically reset after a duration configurable using `APPNET_AGENT_LOGGING_RESET_TIMEOUT` variable.
* `GET /stats/prometheus`: Returns Envoy statistics in Prometheus format.
* `GET /stats/prometheus?usedonly`: Only returns statistics that Envoy has updated.
* `GET /stats/prometheus?filter=metrics_extension`: Filters and returns only the statistics generated by [Metrics Extension](https://docs.aws.amazon.com/app-mesh/latest/userguide/metrics.html#metrics-extension). Can be used in conjunction with `usedonly` parameter.
* `GET /stats/prometheus?usedonly&filter=metrics_extension&delta`: Returns a delta of the statistics computed using the latest snapshot retrieved from Envoy. Requires enabling the snapshotter using `ENABLE_STATS_SNAPSHOT` variable.


## Contributing

Contributions and feedback are welcome! Proposals and pull requests will be considered and responded to. For more information, see the [CONTRIBUTING](CONTRIBUTING.md) file.

If you have a bug/and issue around the behavior of the Amazon ECS Service Connect Agent, please open it here.

If you have a feature request, please open it over at the [AWS Containers Roadmap](https://github.com/aws/containers-roadmap).


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.


## License

This project is licensed under the Apache-2.0 License.
