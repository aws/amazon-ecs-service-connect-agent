// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/env"
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/mesh_resource"
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/metric_filter"
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/netinfo"
	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/platforminfo"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-xray-sdk-go/strategy/sampling"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	boot "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	grpc_cred "github.com/envoyproxy/go-control-plane/envoy/config/grpc_credential/v3"
	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	trace "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	file_access_log "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"

	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"github.com/stoewer/go-strcase"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	// Matches just the port part of an v4 or v6 ip address, compiled eagerly to validate regex
	ipPortRegex = regexp.MustCompile("(?:(?:.+)|(?:::.+)):([0-9]{1,5})")
)

const (
	staticResourcesKey = "staticResources"
	tracingKey         = "tracing"
	statsConfigKey     = "statsConfig"
	statsSinksKey      = "statsSinks"
)

type FileUtil interface {
	Read(path string) ([]byte, error)
	Write(path string, data []byte, perm fs.FileMode) error
}

type fileUtil struct{}

func (f *fileUtil) Read(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func (f *fileUtil) Write(path string, data []byte, perm fs.FileMode) error {
	return ioutil.WriteFile(path, data, perm)
}

// This will be passed to Envoy as its initial set of runtime config.
// This is where we opt in or out of features or special hacks at startup.
func getRuntimeConfigLayer0() (map[string]interface{}, error) {

	setTracingDecision, err := env.TruthyOrElse("APPMESH_SET_TRACING_DECISION", true)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		// Allow all deprecated features to be enabled by Envoy. This prevents warnings or hard errors when
		// it is sent config that is being deprecated.
		"envoy.features.enable_all_deprecated_features": true,

		// Best-effort support xDSv2 config if we see it.
		"envoy.reloadable_features.enable_deprecated_v2_api": true,

		// Allow RE2 regexes of effectively any complexity
		"re2.max_program_size.error_level": 1000,

		// This is a temporary hack flag to tell Envoy not to mutate
		// tracing headers that it did not originate.
		"envoy.reloadable_features.http_set_tracing_decision_in_request_id": setTracingDecision,
	}, nil
}

func getMeshResourceFromNodeId(nodeId string) (*mesh_resource.MeshResource, error) {
	// The resource name may not be a fully-formed ARN
	// It is perfectly valid to pass strings or these 2 forms:
	// 1. arn:aws:appmesh:...:mesh/meshName/resourceType/resourceName
	// 2. mesh/meshName/resourceType/resourceName
	nodeIdBits := strings.Split(nodeId, "/")
	if len(nodeIdBits) < 4 {
		return nil, fmt.Errorf("Unrecognized resource name format: %s", nodeId)
	}
	return &mesh_resource.MeshResource{
		MeshName:           nodeIdBits[1],
		Type:               nodeIdBits[2],
		UpperCamelCaseType: strcase.UpperCamelCase(nodeIdBits[2]),
		SnakeCaseType:      strcase.SnakeCase(nodeIdBits[2]),
		Name:               nodeIdBits[3],
	}, nil
}

func mergeDstMapInterfaceWithSrc(dst, src map[string]interface{}) (map[string]interface{}, error) {
	// Create an array of keys first so that we don't iterate directly over src of type
	// `map[string]interface{}` which can get modified when normalized inside the for loop.
	var keys []string
	for key, _ := range src {
		keys = append(keys, key)
	}
	for _, key := range keys {
		value := src[key]
		keyInLowerCamelCase := strcase.LowerCamelCase(key)
		if _, err := normalizeMapKeyToCamelCase(src, key); err != nil {
			// Error if we fail to normalize input as it contains both snake_case & lowerCamelCase for the same key.
			return nil, err
		}
		if oldValue, ok := dst[keyInLowerCamelCase]; ok {
			// If there is an existing value for the key, then give a warning about replacing the existing value.
			existing, _ := yaml.Marshal(map[string]interface{}{keyInLowerCamelCase: oldValue})
			incoming, _ := yaml.Marshal(map[string]interface{}{key: value})
			log.Warnf("replacing an existing %s config", keyInLowerCamelCase)
			log.Warnf("==OLD==\n---\n%s", string(existing))
			log.Warnf("==NEW==\n---\n%s", string(incoming))
		}
		dst[keyInLowerCamelCase] = value
	}
	return dst, nil
}

func extendDstMapInterfaceWithSrcForAKey(dst, src map[string]interface{}, key string) map[string]interface{} {
	if srcValue, ok := src[key]; ok {
		if dstValue, ok := dst[key]; ok {
			dst[key] = reflect.AppendSlice(reflect.ValueOf(dstValue), reflect.ValueOf(srcValue)).Interface()
		} else {
			dst[key] = srcValue
		}
	}
	return dst
}

func getRegion() (string, error) {
	if r := env.Get("AWS_REGION"); r != "" {
		return r, nil
	}
	log.Info("AWS_REGION environment variable is not set. Will fetch region from EC2 Metadata Service...")
	sess, err := session.NewSession()
	if err != nil {
		return "", err
	}
	md := ec2metadata.New(sess)
	return md.Region()
}

// China regions have a different domain. Refer official link:
// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-arns.html
func getXdsDomain(region string) string {
	xdsDomain := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		xdsDomain = "amazonaws.com.cn"
	}
	return xdsDomain
}

func getXdsEndpoint(region string) (string, error) {
	if v := env.Get("APPMESH_XDS_ENDPOINT"); v != "" {
		return v, nil
	}
	preview, err := env.Truthy("APPMESH_PREVIEW")
	if err != nil {
		return "", err
	}
	if preview {
		return fmt.Sprintf("appmesh-preview-envoy-management.%s.%s:443", region, getXdsDomain(region)), nil
	}
	return fmt.Sprintf("appmesh-envoy-management.%s.%s:443", region, getXdsDomain(region)), nil
}

func getSigningName() (string, error) {
	if v := env.Get("APPMESH_SIGNING_NAME"); v != "" {
		return v, nil
	}
	preview, err := env.Truthy("APPMESH_PREVIEW")
	if err != nil {
		return "", err
	}
	if preview {
		return "appmesh-preview", nil
	}
	return "appmesh", nil
}

func getNodeId() (string, error) {
	// Prefer APPMESH_RESOURCE_ARN
	// fallback to APPMESH_RESOURCE_NAME and APPMESH_VIRTUAL_NODE_NAME in order, for compatability
	if ra := env.Get("APPMESH_RESOURCE_ARN"); ra != "" {
		return ra, nil
	} else if rn := env.Get("APPMESH_RESOURCE_NAME"); rn != "" {
		return rn, nil
	} else if vn := env.Get("APPMESH_VIRTUAL_NODE_NAME"); vn != "" {
		return vn, nil
	} else {
		return "", errors.New("APPMESH_RESOURCE_ARN environment variable must be set.")
	}
}

func getNodeCluster(nodeId string) string {
	// Prefer APPMESH_RESOURCE_CLUSTER
	// fallback to APPMESH_VIRTUAL_NODE_CLUSTER for compatability
	// and finally to the nodeId
	if v := env.Get("APPMESH_RESOURCE_CLUSTER"); v != "" {
		return v
	}
	if v := env.Get("APPMESH_VIRTUAL_NODE_CLUSTER"); v != "" {
		return v
	}
	return nodeId
}

func normalizeMapKeyToCamelCase(m map[string]interface{}, key string) (map[string]interface{}, error) {
	// This function will normalize the input `m` map[string]interface{} to contain only the lowerCamelCase format of
	// the input `key`. The input `m` map[string]interface{} can contain the key either as lowerCamelCase or as
	// snake_case type. But if it contains both case type for the same `key` then this function will throw an error.
	// Eg: If 'statsConfig' is the key then `m` cannot contain both 'statsConfig' & 'stats_config'.
	key_in_snake_case := strcase.SnakeCase(key)
	keyInLowerCamelCase := strcase.LowerCamelCase(key)
	if key_in_snake_case == keyInLowerCamelCase {
		// Input contains a single word where snake_case and camelCase string are the same. Eg: tracing.
		return m, nil
	}
	if _, ok := m[key_in_snake_case]; !ok {
		// Nothing to normalize.
		return m, nil
	}
	if _, ok := m[keyInLowerCamelCase]; ok {
		return nil, fmt.Errorf("the config contains both %s(lowerCamelCase) & "+
			"%s(snake_case), specify only one of them\n", keyInLowerCamelCase, key_in_snake_case)
	} else {
		// If snake_case is used in input `m`, convert that to lowerCamelCase.
		m[keyInLowerCamelCase] = m[key_in_snake_case]
		delete(m, key_in_snake_case)
	}
	return m, nil
}

func buildTcpSocketAddr(addr string, port int) *core.Address {
	return &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Address: addr,
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: uint32(port),
				},
			},
		},
	}
}

func buildUdpSocketAddr(addr string, port int) *core.Address {
	return &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.SocketAddress_UDP,
				Address:  addr,
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: uint32(port),
				},
			},
		},
	}
}

func buildSocketPipe(udsPath string) *core.Address {
	return &core.Address{
		Address: &core.Address_Pipe{
			Pipe: &core.Pipe{
				Path: udsPath,
			},
		},
	}
}

func buildAdminAccessLogConfig() (*accesslog.AccessLog, error) {
	logPath := env.Or("ENVOY_ADMIN_ACCESS_LOG_FILE", "/tmp/envoy_admin_access.log")
	logPathConfig, err := anypb.New(&file_access_log.FileAccessLog{
		Path: logPath,
	})

	if err != nil {
		return nil, err
	}

	return &accesslog.AccessLog{
		ConfigType: &accesslog.AccessLog_TypedConfig{
			TypedConfig: logPathConfig,
		},
	}, nil
}

func buildAdmin() (*boot.Admin, error) {
	port, err := env.OrInt("ENVOY_ADMIN_ACCESS_PORT", 9901)
	if err != nil {
		return nil, err
	}

	accessLogConfig, err := buildAdminAccessLogConfig()

	if err != nil {
		return nil, err
	}

	return &boot.Admin{
		AccessLog: []*accesslog.AccessLog{
			accessLogConfig,
		},
		Address: buildTcpSocketAddr("0.0.0.0", port),
	}, nil
}

func buildNode(id string, cluster string, metadata *structpb.Struct) *core.Node {
	return &core.Node{
		Id:       id,
		Cluster:  cluster,
		Metadata: metadata,
	}
}

func generateStaticRuntimeLayer(s *structpb.Struct) *boot.RuntimeLayer {
	return &boot.RuntimeLayer{
		Name: "static_layer_0",
		LayerSpecifier: &boot.RuntimeLayer_StaticLayer{
			StaticLayer: s,
		},
	}
}

func generateEmptyAdminLayer() *boot.RuntimeLayer {
	return &boot.RuntimeLayer{
		Name: "admin_layer",
		LayerSpecifier: &boot.RuntimeLayer_AdminLayer_{
			AdminLayer: nil,
		},
	}
}

func buildLayeredRuntime() (*boot.LayeredRuntime, error) {
	config, err := getRuntimeConfigLayer0()
	if err != nil {
		return nil, err
	}

	s, err := structpb.NewStruct(config)
	if err != nil {
		return nil, err
	}
	return &boot.LayeredRuntime{
		Layers: []*boot.RuntimeLayer{
			generateStaticRuntimeLayer(s),
			generateEmptyAdminLayer(),
		},
	}, nil
}

func buildClusterManager() *boot.ClusterManager {
	logPath := env.Or("ENVOY_OUTLIER_DETECTION_EVENT_LOG_PATH", "/dev/stdout")
	return &boot.ClusterManager{
		OutlierDetection: &boot.ClusterManager_OutlierDetection{
			EventLogPath: logPath,
		},
	}
}

func buildFileDataSource(filename string) *core.DataSource {
	return &core.DataSource{
		Specifier: &core.DataSource_Filename{
			Filename: filename,
		},
	}
}

func buildGoogleGrpcIntChannelArg(value int64) *core.GrpcService_GoogleGrpc_ChannelArgs_Value {
	return &core.GrpcService_GoogleGrpc_ChannelArgs_Value{
		ValueSpecifier: &core.GrpcService_GoogleGrpc_ChannelArgs_Value_IntValue{
			IntValue: value,
		},
	}
}

func buildAdsGrpcService(endpoint string, region string, signingName string) (*core.GrpcService, error) {
	iamConfig, err := anypb.New(&grpc_cred.AwsIamConfig{
		ServiceName: signingName,
		Region:      region,
	})
	if err != nil {
		return nil, err
	}
	return &core.GrpcService{
		TargetSpecifier: &core.GrpcService_GoogleGrpc_{
			GoogleGrpc: &core.GrpcService_GoogleGrpc{
				StatPrefix: "ads",
				TargetUri:  endpoint,
				ChannelCredentials: &core.GrpcService_GoogleGrpc_ChannelCredentials{
					CredentialSpecifier: &core.GrpcService_GoogleGrpc_ChannelCredentials_SslCredentials{
						SslCredentials: &core.GrpcService_GoogleGrpc_SslCredentials{
							RootCerts: buildFileDataSource("/etc/pki/tls/cert.pem"),
						},
					},
				},
				CredentialsFactoryName: "envoy.grpc_credentials.aws_iam",
				CallCredentials: []*core.GrpcService_GoogleGrpc_CallCredentials{
					&core.GrpcService_GoogleGrpc_CallCredentials{
						CredentialSpecifier: &core.GrpcService_GoogleGrpc_CallCredentials_FromPlugin{
							FromPlugin: &core.GrpcService_GoogleGrpc_CallCredentials_MetadataCredentialsFromPlugin{
								Name: "envoy.grpc_credentials.aws_iam",
								ConfigType: &core.GrpcService_GoogleGrpc_CallCredentials_MetadataCredentialsFromPlugin_TypedConfig{
									TypedConfig: iamConfig,
								},
							},
						},
					},
				},
				ChannelArgs: &core.GrpcService_GoogleGrpc_ChannelArgs{
					Args: map[string]*core.GrpcService_GoogleGrpc_ChannelArgs_Value{
						"grpc.http2.max_pings_without_data": buildGoogleGrpcIntChannelArg(0),
						"grpc.keepalive_time_ms":            buildGoogleGrpcIntChannelArg(10000),
						"grpc.keepalive_timeout_ms":         buildGoogleGrpcIntChannelArg(20000),
					},
				},
			},
		},
	}, nil
}

// Make the config source used to point things like LDS or CDS to ADS
func buildAdsConfigSource() (*core.ConfigSource, error) {
	// This timeout is in seconds
	timeout, err := env.OrInt("ENVOY_INITIAL_FETCH_TIMEOUT", 0)
	if err != nil {
		return nil, err
	}
	return &core.ConfigSource{
		InitialFetchTimeout: &durationpb.Duration{
			Seconds: int64(timeout),
		},
		ConfigSourceSpecifier: &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		},
		ResourceApiVersion: core.ApiVersion_V3,
	}, nil
}

func buildDynamicResources(endpoint string, region string, signingName string) (*boot.Bootstrap_DynamicResources, error) {
	ads, err := buildAdsGrpcService(endpoint, region, signingName)
	if err != nil {
		return nil, err
	}
	configSource, err := buildAdsConfigSource()
	if err != nil {
		return nil, err
	}
	dr := &boot.Bootstrap_DynamicResources{
		AdsConfig: &core.ApiConfigSource{
			TransportApiVersion: core.ApiVersion_V3,
			ApiType:             core.ApiConfigSource_GRPC,
			GrpcServices: []*core.GrpcService{
				ads,
			},
		},
		LdsConfig: configSource,
		CdsConfig: configSource,
	}
	return dr, nil
}

func getXRayAddressAndPort() (string, int, error) {
	port, err := env.OrInt("XRAY_DAEMON_PORT", 2000)
	if err != nil {
		return "", 0, err
	}
	addr := "127.0.0.1"
	// AWS_XRAY_DAEMON_ADDRESS may contain a port, if it does it takes priorty over XRAY_DAEMON_PORT
	if v := env.Get("AWS_XRAY_DAEMON_ADDRESS"); v != "" {
		// We use regex to first check that we have a port since the
		// net.SplitHostPort method requires a port exist...
		if len(ipPortRegex.FindSubmatchIndex([]byte(v))) != 0 {
			host, p, err := net.SplitHostPort(v)
			if err != nil {
				return "", 0, fmt.Errorf("Could not parse AWS_XRAY_DAEMON_ADDRESS: \"%s\".", v)
			}
			i, err := strconv.ParseInt(p, 10, strconv.IntSize)
			if err != nil {
				return "", 0, fmt.Errorf("Could not parse AWS_XRAY_DAEMON_ADDRESS: \"%s\".", v)
			}
			port = int(i)
			addr = host
		} else {
			addr = v
		}
		// The x-ray address must be a static IP right now since
		// the extension does not support pointing to a cluster
		if net.ParseIP(addr) == nil {
			return "", 0, fmt.Errorf("AWS_XRAY_DAEMON_ADDRESS must be a static IPv4 or IPv6 address such as \"127.0.0.1\".")
		}
	}

	return addr, port, nil
}

func getXraySamplingRuleManifest(fileUtil FileUtil) (string, error) {
	// This function will try to get the file path for the xray sampling rule manifest.
	// The input can either be the json file specified via XRAY_SAMPLING_RULE_MANIFEST
	// or just the sampling rate specified via XRAY_SAMPLING_RATE env variable.
	// For more info about the format and specification of this json file refer xray docs at
	// https://docs.aws.amazon.com/xray/latest/devguide/xray-sdk-go-configuration.html#xray-sdk-go-configuration-sampling
	const envSrmKey = "XRAY_SAMPLING_RULE_MANIFEST"
	const envSrKey = "XRAY_SAMPLING_RATE"
	const srmFile = "/tmp/sampling-rules.json"
	const defaultFixedTarget = int64(1)
	const defaultVersion = int(2)
	const unsupportedVersion = int(1)

	if v := env.Get(envSrmKey); v != "" {
		// XRAY_SAMPLING_RULE_MANIFEST is given so validate the json file it points to.
		if data, err := fileUtil.Read(v); err != nil {
			return "", fmt.Errorf("could not read file %s=\"%s\": %w", envSrmKey, v, err)
		} else if ruleManifest, err := sampling.ManifestFromJSONBytes(data); err != nil {
			// ManifestFromJSONBytes method from aws xray go sdk will parse the data and validate.
			return "", fmt.Errorf("validation failed for file %s=\"%s\": %w", envSrmKey, v, err)
		} else if unsupportedVersion == ruleManifest.Version {
			// Sampling manifest can have two possible versions (1 & 2) but envoy xray extension doesn't support version 1.
			return "", fmt.Errorf("validation failed for file %s=\"%s\": version %d is not supported", envSrmKey, v, ruleManifest.Version)
		} else {
			log.Infof("%s is defined as %s, merging it with the x-ray tracing config.", envSrmKey, v)
			return v, nil
		}
	} else if v := env.Get(envSrKey); v != "" {
		// XRAY_SAMPLING_RULE_MANIFEST is not given but XRAY_SAMPLING_RATE is given so create the sampling-rules.json.
		var fixedRate float64
		var err error
		// The fixed rate is a decimal between 0 and 1.00 (100%).
		if fixedRate, err = strconv.ParseFloat(v, 32); err != nil || float64(0) > fixedRate || float64(1) < fixedRate {
			return "", fmt.Errorf("%s environment variable (\"%s\") must be a decimal between 0 and 1.00 (100%%)", envSrKey, v)
		}
		// Round off to the nearest 2 decimal point precision.
		fixedRate = math.Round(fixedRate*100) / 100
		// If fixed rate is 0.05 (5%) then no-op
		if fixedRate == 0.05 {
			log.Infof("%s is defined as %s, but not creating a sampling manifest as ~0.05 is the X-Ray default", envSrKey, v)
			return "", nil
		}
		localManifest := &sampling.RuleManifest{
			Version: defaultVersion,
			Default: &sampling.Rule{
				Properties: &sampling.Properties{
					FixedTarget: defaultFixedTarget,
					Rate:        fixedRate,
				},
			},
			Rules: []*sampling.Rule{},
		}
		if data, err := json.Marshal(localManifest); err != nil {
			return "", err
		} else if err = fileUtil.Write(srmFile, data, 0644); err != nil {
			return "", err
		} else {
			log.Infof("%s is defined as %s, localized sampling rate is set to %.2f (%d%%)", envSrmKey, v, fixedRate, int(fixedRate*100))
			return srmFile, nil
		}
	}
	return "", nil
}

func appendXRayTracing(b *boot.Bootstrap, nodeId string, cluster string, fileUtil FileUtil) error {
	addr, port, err := getXRayAddressAndPort()
	if err != nil {
		return err
	}

	cfg := &trace.XRayConfig{
		SegmentName: cluster,
		DaemonEndpoint: &core.SocketAddress{
			Protocol: core.SocketAddress_UDP,
			Address:  addr,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: uint32(port),
			},
		},
		SegmentFields: &trace.XRayConfig_SegmentFields{
			Origin: "AWS::AppMesh::Proxy",
		},
	}

	if samplingRuleManifest, err := getXraySamplingRuleManifest(fileUtil); err != nil {
		return err
	} else if samplingRuleManifest != "" {
		cfg.SamplingRuleManifest = buildFileDataSource(samplingRuleManifest)
	}

	res, err := getMeshResourceFromNodeId(nodeId)
	if err == nil {
		// By default we want the segment name to be in this format:
		// meshName/resourceName
		// This is weird but how the x-ray tracer has always done it.
		// If we can't parse the node name, we'll just pass the cluster name through.
		cfg.SegmentName = res.MeshName + "/" + res.Name

		// If we can determine the resource name and type, we add that to the xray config as well
		// TODO: Doubt x-ray supports "virtual_gateway_name" so for now we
		// will always pass them "virtual_node_name". This shouldnt result in difference to a user
		// as it is just presented as the "AWS::AppMesh::Proxy" name in x-ray.
		aws, err := structpb.NewStruct(map[string]interface{}{
			// NOTE: The config for this field *really is* just a schema-less struct in Envoy
			//  it is passed through to the xray daemon unmodified.
			"app_mesh": map[string]interface{}{
				"mesh_name":         res.MeshName,
				"virtual_node_name": res.Name,
			},
		})
		if err != nil {
			return err
		}
		cfg.SegmentFields.Aws = aws

	} else {
		// This is non-fatal though. We still can enable tracing without being able to parse the name
		log.Warn(err)
	}

	packedCfg, err := anypb.New(cfg)
	if err != nil {
		return err
	}

	bt := &boot.Bootstrap{
		Tracing: &trace.Tracing{
			Http: &trace.Tracing_Http{
				Name: "envoy.tracers.xray",
				ConfigType: &trace.Tracing_Http_TypedConfig{
					TypedConfig: packedCfg,
				},
			},
		},
	}
	return mergeBootstrap(b, bt)
}

func appendDataDogTracing(b *boot.Bootstrap, nodeId string) error {
	port, err := env.OrInt("DATADOG_TRACER_PORT", 8126)
	if err != nil {
		return err
	}
	addr := env.Or("DATADOG_TRACER_ADDRESS", "127.0.0.1")

	// Generate a name for the Envoy segment of the trace
	// similarly to how we generate it for X-Ray: meshName/resourceName
	// But defer to whatever is specified in the DD_SERVICE env var
	serviceName := "envoy"
	res, err := getMeshResourceFromNodeId(nodeId)
	if err == nil {
		serviceName = "envoy-" + res.MeshName + "/" + res.Name
	}

	packedCfg, err := anypb.New(&trace.DatadogConfig{
		CollectorCluster: "datadog_agent",
		ServiceName:      env.Or("DD_SERVICE", serviceName),
	})
	if err != nil {
		return err
	}
	bt := &boot.Bootstrap{
		Tracing: &trace.Tracing{
			Http: &trace.Tracing_Http{
				Name: "envoy.tracers.datadog",
				ConfigType: &trace.Tracing_Http_TypedConfig{
					TypedConfig: packedCfg,
				},
			},
		},
		StaticResources: &boot.Bootstrap_StaticResources{
			Clusters: []*cluster.Cluster{
				&cluster.Cluster{
					Name: "datadog_agent",
					ConnectTimeout: &durationpb.Duration{
						Seconds: 1,
					},
					ClusterDiscoveryType: &cluster.Cluster_Type{
						Type: cluster.Cluster_STRICT_DNS,
					},
					LbPolicy: cluster.Cluster_ROUND_ROBIN,
					LoadAssignment: &endpoint.ClusterLoadAssignment{
						ClusterName: "datadog_agent",
						Endpoints: []*endpoint.LocalityLbEndpoints{
							&endpoint.LocalityLbEndpoints{
								LbEndpoints: []*endpoint.LbEndpoint{
									&endpoint.LbEndpoint{
										HostIdentifier: &endpoint.LbEndpoint_Endpoint{
											Endpoint: &endpoint.Endpoint{
												Address: buildTcpSocketAddr(addr, port),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return mergeBootstrap(b, bt)
}

func appendJaegerTracing(b *boot.Bootstrap) error {
	port, err := env.OrInt("JAEGER_TRACER_PORT", 9411)
	if err != nil {
		return err
	}
	addr := env.Or("JAEGER_TRACER_ADDRESS", "127.0.0.1")

	packedCfg, err := anypb.New(&trace.ZipkinConfig{
		CollectorCluster:         "jaeger",
		CollectorEndpoint:        "/api/v2/spans",
		CollectorEndpointVersion: trace.ZipkinConfig_HTTP_PROTO,
		SharedSpanContext:        wrapperspb.Bool(false),
	})
	if err != nil {
		return err
	}
	bt := &boot.Bootstrap{
		Tracing: &trace.Tracing{
			Http: &trace.Tracing_Http{
				Name: "envoy.tracers.zipkin",
				ConfigType: &trace.Tracing_Http_TypedConfig{
					TypedConfig: packedCfg,
				},
			},
		},
		StaticResources: &boot.Bootstrap_StaticResources{
			Clusters: []*cluster.Cluster{
				&cluster.Cluster{
					Name: "jaeger",
					ConnectTimeout: &durationpb.Duration{
						Seconds: 1,
					},
					ClusterDiscoveryType: &cluster.Cluster_Type{
						Type: cluster.Cluster_STRICT_DNS,
					},
					LbPolicy: cluster.Cluster_ROUND_ROBIN,
					LoadAssignment: &endpoint.ClusterLoadAssignment{
						ClusterName: "jaeger",
						Endpoints: []*endpoint.LocalityLbEndpoints{
							&endpoint.LocalityLbEndpoints{
								LbEndpoints: []*endpoint.LbEndpoint{
									&endpoint.LbEndpoint{
										HostIdentifier: &endpoint.LbEndpoint_Endpoint{
											Endpoint: &endpoint.Endpoint{
												Address: buildTcpSocketAddr(addr, port),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return mergeBootstrap(b, bt)
}

func appendSdsSocketCluster(b *boot.Bootstrap, socketPath string) error {
	bt := &boot.Bootstrap{
		StaticResources: &boot.Bootstrap_StaticResources{
			Clusters: []*cluster.Cluster{
				&cluster.Cluster{
					Name: "static_cluster_sds_unix_socket",
					ConnectTimeout: &durationpb.Duration{
						Seconds: 1,
					},
					Http2ProtocolOptions: &core.Http2ProtocolOptions{},
					ClusterDiscoveryType: &cluster.Cluster_Type{
						Type: cluster.Cluster_STATIC,
					},
					LoadAssignment: &endpoint.ClusterLoadAssignment{
						ClusterName: "static_cluster_sds_unix_socket",
						Endpoints: []*endpoint.LocalityLbEndpoints{
							&endpoint.LocalityLbEndpoints{
								LbEndpoints: []*endpoint.LbEndpoint{
									&endpoint.LbEndpoint{
										HostIdentifier: &endpoint.LbEndpoint_Endpoint{
											Endpoint: &endpoint.Endpoint{
												Address: &core.Address{
													Address: &core.Address_Pipe{
														Pipe: &core.Pipe{
															Path: socketPath,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return mergeBootstrap(b, bt)
}

func mergeBootstrap(dst *boot.Bootstrap, src *boot.Bootstrap) error {
	// Tracing should not be merged
	if src.Tracing != nil {
		if dst.Tracing != nil {
			return errors.New("Multiple tracing configurations were specified.")
		}
		dst.Tracing = src.Tracing
	}

	// Stats configs should not be merged
	if src.StatsConfig != nil {
		if dst.StatsConfig != nil {
			return errors.New("Multiple stats configurations were specified.")
		}
		dst.StatsConfig = src.StatsConfig
	}

	dst.StatsSinks = append(dst.StatsSinks, src.StatsSinks...)

	if src.StaticResources != nil {
		if dst.StaticResources == nil {
			dst.StaticResources = &boot.Bootstrap_StaticResources{}
		}
		proto.Merge(dst.StaticResources, src.StaticResources)
	}
	return nil
}

func appendTracing(b *boot.Bootstrap, nodeId string, cluster string, fileUtil FileUtil) error {
	xr, err := env.Truthy("ENABLE_ENVOY_XRAY_TRACING")
	if err != nil {
		return err
	}
	dd, err := env.Truthy("ENABLE_ENVOY_DATADOG_TRACING")
	if err != nil {
		return err
	}
	jg, err := env.Truthy("ENABLE_ENVOY_JAEGER_TRACING")
	if err != nil {
		return err
	}
	if (xr && dd) || (xr && jg) || (dd && jg) {
		return errors.New("Only a single envoy trace driver can be configured; please enable only one of ENABLE_ENVOY_XRAY_TRACING, ENABLE_ENVOY_DATADOG_TRACING or ENABLE_ENVOY_JAEGER_TRACING.")
	}
	if xr {
		return appendXRayTracing(b, nodeId, cluster, fileUtil)
	} else if dd {
		return appendDataDogTracing(b, nodeId)
	} else if jg {
		return appendJaegerTracing(b)
	}
	return nil
}

func appendStats(b *boot.Bootstrap, nodeId string) error {
	res, err := getMeshResourceFromNodeId(nodeId)
	if err != nil {
		return err
	}
	tags := make([]*metrics.TagSpecifier, 0)

	enableStatsTags, err := env.Truthy("ENABLE_ENVOY_STATS_TAGS")
	if err != nil {
		return err
	}
	if enableStatsTags {
		tags = append(tags, &metrics.TagSpecifier{
			TagName: "appmesh.mesh",
			TagValue: &metrics.TagSpecifier_FixedValue{
				FixedValue: res.MeshName,
			},
		})

		tags = append(tags, &metrics.TagSpecifier{
			TagName: "appmesh." + res.SnakeCaseType,
			TagValue: &metrics.TagSpecifier_FixedValue{
				FixedValue: res.Name,
			},
		})
	}

	if err := metric_filter.AppendStatsTagRegex(&tags, res); err != nil {
		return err
	}

	// If there are no tags, then just bail out
	if len(tags) == 0 {
		return nil
	}
	bt := &boot.Bootstrap{
		StatsConfig: &metrics.StatsConfig{
			StatsTags: tags,
		},
	}
	return mergeBootstrap(b, bt)
}

func appendStatsFlushInterval(b *boot.Bootstrap, interval string) error {
	d, err := time.ParseDuration(interval)
	if err != nil {
		return err
	}
	pbd := durationpb.New(d)
	if err := pbd.CheckValid(); err != nil {
		return err
	}
	b.StatsFlushInterval = pbd
	return nil
}

func appendDogStatsDSinks(b *boot.Bootstrap) error {
	var packedCfg *anypb.Any
	var err error
	if udsPath := env.Get("STATSD_SOCKET_PATH"); udsPath != "" {
		packedCfg, err = anypb.New(&metrics.DogStatsdSink{
			DogStatsdSpecifier: &metrics.DogStatsdSink_Address{
				Address: buildSocketPipe(udsPath),
			},
		})
		if err != nil {
			return err
		}
	} else {
		addr := env.Or("STATSD_ADDRESS", "127.0.0.1")
		port, err := env.OrInt("STATSD_PORT", 8125)
		if err != nil {
			return err
		}
		packedCfg, err = anypb.New(&metrics.DogStatsdSink{
			DogStatsdSpecifier: &metrics.DogStatsdSink_Address{
				Address: buildUdpSocketAddr(addr, port),
			},
		})
		if err != nil {
			return err
		}
	}

	bt := &boot.Bootstrap{
		StatsSinks: []*metrics.StatsSink{
			&metrics.StatsSink{
				Name: "envoy.stat_sinks.dog_statsd",
				ConfigType: &metrics.StatsSink_TypedConfig{
					TypedConfig: packedCfg,
				},
			},
		},
	}
	return mergeBootstrap(b, bt)
}

func mergeStaticResourcesMaps(dst, src map[string]interface{}) (map[string]interface{}, error) {
	if _, ok := src[staticResourcesKey].(map[string]interface{}); !ok {
		// Just return dst if src is empty and there is nothing to merge
		return dst, nil
	}
	srcSr := src[staticResourcesKey].(map[string]interface{})
	if _, ok := dst[staticResourcesKey].(map[string]interface{}); !ok {
		// Just set src staticResources as dst staticResources if dst staticResources is empty
		dst[staticResourcesKey] = srcSr
		return dst, nil
	}
	dstSr := dst[staticResourcesKey].(map[string]interface{})
	// Merge the config.bootstrap.v3.Bootstrap.StaticResources as given in the envoyproxy docs at
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/bootstrap/v3/bootstrap.proto#config-bootstrap-v3-bootstrap-staticresources
	for _, key := range [...]string{"listeners", "clusters", "secrets"} {
		dstSr = extendDstMapInterfaceWithSrcForAKey(dstSr, srcSr, key)
	}
	dst[staticResourcesKey] = dstSr
	return dst, nil
}

func mergeCustomConfigMaps(dst, src map[string]interface{}) (map[string]interface{}, error) {
	// Tracing should not be merged also no need to case sanitize for tracing as it is a single word.
	if srcTracing, ok := src[tracingKey]; ok {
		if _, ok := dst[tracingKey]; ok {
			return nil, fmt.Errorf("multiple tracing configurations were specified")
		}
		dst[tracingKey] = srcTracing
		log.Info("Tracing config merged")
	}

	// Stats configs should not be merged
	src, err := normalizeMapKeyToCamelCase(src, statsConfigKey)
	if err != nil {
		return nil, err
	}
	if srcStats, ok := src[statsConfigKey]; ok {
		if _, ok := dst[statsConfigKey]; ok {
			return nil, fmt.Errorf("multiple stats configurations were specified")
		}
		dst[statsConfigKey] = srcStats
		log.Info("Stats config merged")
	}

	// Stats sinks are appended
	src, err = normalizeMapKeyToCamelCase(src, statsSinksKey)
	if err != nil {
		return nil, err
	}
	dst = extendDstMapInterfaceWithSrcForAKey(dst, src, statsSinksKey)

	// The bootstrap static resources could be part of any config supplied, so merge for all.
	// Expect Static Resources to be provided either via staticResources (lowerCamelCase) key or via
	// static_resources (snake_case) key. If both are provided then below func call will error out.
	src, err = normalizeMapKeyToCamelCase(src, staticResourcesKey)
	if err != nil {
		return nil, err
	}
	dst, err = mergeStaticResourcesMaps(dst, src)
	if err != nil {
		return nil, err
	}

	// Merge rest of the bootstrap configurations except for the resource which are explicitly merged above
	// in the previous steps. All the bootstrap resources list can be found in the envoy docs at
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/bootstrap/v3/bootstrap.proto#config-bootstrap-v3-bootstrap
	for _, key := range [...]string{tracingKey, statsConfigKey, statsSinksKey, staticResourcesKey} {
		delete(src, key)
	}
	if dst, err = mergeDstMapInterfaceWithSrc(dst, src); err != nil {
		return nil, err
	}

	return dst, nil
}

func mergeCustomConfigs(bootYaml []byte, fileUtil FileUtil) ([]byte, error) {
	// Merge any custom configs specified via env variable without any protobuf validations
	bootConfig := make(map[string]interface{})
	if bootYaml != nil {
		if err := yaml.Unmarshal(bootYaml, &bootConfig); err != nil {
			return nil, err
		}
	}

	envVariables := [...]string{
		"ENVOY_TRACING_CFG_FILE",     // tracing
		"ENVOY_STATS_CONFIG_FILE",    // stats
		"ENVOY_STATS_SINKS_CFG_FILE", // stats sinks
	}

	for _, envVar := range envVariables {
		if v := env.Get(envVar); v != "" {
			log.Infof("%s is defined as %s, merging it with the envoy config.", envVar, v)

			data, err := fileUtil.Read(v)
			if err != nil {
				return nil, err
			}
			var customConfig map[string]interface{}
			if err := yaml.Unmarshal(data, &customConfig); err != nil {
				return nil, fmt.Errorf("failure to parse %s %s for the reason: %w", envVar, v, err)
			}
			if len(customConfig) == 0 {
				return nil, fmt.Errorf("Specified %s %s is empty.", envVar, v)
			}
			// We have found some users putting unrelated configs in these files, so we
			// best treat it like generic envoy config.
			// ref: https://code.amazon.com/reviews/CR-32715565
			bootConfig, err = mergeCustomConfigMaps(bootConfig, customConfig)
			if err != nil {
				return nil, fmt.Errorf("failure to merge %s %s into envoy config for the reason: %w", envVar, v, err)
			}

			// Any special handling are done in below switch statement
			switch envVar {
			case "ENVOY_STATS_SINKS_CFG_FILE":
				// TODO: Does it make sense to always error here?
				if _, ok := bootConfig[statsSinksKey]; !ok {
					return nil, fmt.Errorf("%s was specified as %s, but contained no valid stats_sinks configuration.", envVar, v)
				}
			}
		}
	}

	// Check if explicit resources are supplied via ENVOY_RESOURCES_CONFIG_FILE
	// This block doesn't have to be inside the above 'for' loop since we treat missing config differently. But
	// TODO: if you feel like this can be inside the 'for' loop feel free move it in: always 'less code' ==> 'less bugs'.
	envVar := "ENVOY_RESOURCES_CONFIG_FILE"
	if v := env.Get(envVar); v != "" {
		log.Infof("Explicitly appending supplied Envoy resources %s %s.", envVar, v)
		data, err := fileUtil.Read(v)
		if err != nil {
			return nil, err
		}
		var resourcesConfig map[string]interface{}
		if err := yaml.Unmarshal(data, &resourcesConfig); err != nil {
			return nil, fmt.Errorf("failure to parse %s %s for the reason: %w", envVar, v, err)
		}
		if len(resourcesConfig) == 0 {
			log.Warnf("Specified %s %s is empty, but will ignore and continue.", envVar, v)
		} else {
			bootConfig, err = mergeCustomConfigMaps(bootConfig, resourcesConfig)
			if err != nil {
				return nil, fmt.Errorf("failure to merge %s %s into envoy config for the reason: %w", envVar, v, err)
			}
		}
	}

	bootYaml, err := yaml.Marshal(bootConfig)
	if err != nil {
		return nil, err
	}
	return bootYaml, nil
}

func convertToYAML(b *boot.Bootstrap, fileUtil FileUtil) (string, error) {
	j, err := protojson.Marshal(b)
	if err != nil {
		return "", err
	}
	y, err := yaml.JSONToYAML(j)
	if err != nil {
		return "", err
	}
	y, err = mergeCustomConfigs(y, fileUtil)
	if err != nil {
		return "", err
	}

	return string(y), nil
}

func buildMetadataForNode() (*structpb.Struct, error) {
	md := make(map[string]interface{})

	interfaceInfo, err := netinfo.BuildMapWithInterfaceInfo()
	if err != nil {
		log.Warnf("Could not collect network info: %s", err)
	} else {
		for k, v := range *interfaceInfo {
			md[k] = v
		}
	}

	metricFilter, err := metric_filter.BuildMetadata()
	if err != nil {
		log.Warnf("Could not determine metric filter options: %s", err)
	} else {
		for k, v := range *metricFilter {
			md[k] = v
		}
	}

	platformInfo, err := platforminfo.BuildMetadata()
	if err != nil {
		log.Warnf("Could not collect platform info: %s", err)
	} else {
		for k, v := range *platformInfo {
			md[k] = v
		}
	}

	return structpb.NewStruct(md)
}

func bootstrap(fileUtil FileUtil) (*boot.Bootstrap, error) {
	// Check pre-configured ENVOY_CONFIG_FILE
	preConfig := env.Get("ENVOY_CONFIG_FILE")
	if preConfig != "" {
		log.Infof("Using existing Envoy configuration file at %s.", preConfig)
		preConfigBytes, err := fileUtil.Read(preConfig)
		if err != nil {
			return nil, err
		}
		if len(preConfigBytes) == 0 {
			return nil, fmt.Errorf("Specified ENVOY_CONFIG_FILE %s is empty.", preConfig)
		}
		// Writing the entire file into stdout without any protobuf validations
		fmt.Print(string(preConfigBytes))
		return nil, nil
	}

	// Generate new config
	region, err := getRegion()
	if err != nil {
		return nil, err
	}

	signingName, err := getSigningName()
	if err != nil {
		return nil, err
	}

	id, err := getNodeId()
	if err != nil {
		return nil, err
	}

	clusterId := getNodeCluster(id)
	xdsEndpoint, err := getXdsEndpoint(region)
	if err != nil {
		return nil, err
	}

	admin, err := buildAdmin()
	if err != nil {
		return nil, err
	}

	dr, err := buildDynamicResources(xdsEndpoint, region, signingName)
	if err != nil {
		return nil, err
	}

	lr, err := buildLayeredRuntime()
	if err != nil {
		return nil, err
	}

	metadata, err := buildMetadataForNode()
	if err != nil {
		return nil, err
	}

	b := &boot.Bootstrap{
		Admin:            admin,
		Node:             buildNode(id, clusterId, metadata),
		LayeredRuntime:   lr,
		DynamicResources: dr,
		ClusterManager:   buildClusterManager(),
	}

	// Tracing
	if v := env.Get("ENVOY_TRACING_CFG_FILE"); v == "" {
		if err := appendTracing(b, id, clusterId, fileUtil); err != nil {
			return nil, err
		}
	}

	// Unix Domain Socket for SDS Based TLS
	if v := env.Get("APPMESH_SDS_SOCKET_PATH"); v != "" {
		log.Info("APPMESH_SDS_SOCKET_PATH is defined, generating static sds cluster.")
		if err := appendSdsSocketCluster(b, v); err != nil {
			return nil, err
		}
	}

	// Stats
	if env.Get("ENVOY_STATS_CONFIG_FILE") == "" {
		if err := appendStats(b, id); err != nil {
			return nil, err
		}
	}

	// Stats Flush Interval
	if v := env.Get("ENVOY_STATS_FLUSH_INTERVAL"); v != "" {
		if err := appendStatsFlushInterval(b, v); err != nil {
			return nil, err
		}
	}

	// Stats Sinks
	enableDogStatsd, err := env.Truthy("ENABLE_ENVOY_DOG_STATSD")
	if err != nil {
		return nil, err
	}
	if v := env.Get("ENVOY_STATS_SINKS_CFG_FILE"); v == "" && enableDogStatsd {
		if err := appendDogStatsDSinks(b); err != nil {
			return nil, err
		}
	}

	return b, nil
}

func GetBootstrapYaml() (string, error) {
	fileUtilInst := &fileUtil{}
	b, err := bootstrap(fileUtilInst)
	if err != nil {
		log.Errorf("Cannot generate bootstrap config. %v", err)
		return "", err
	}

	configYaml, err := convertToYAML(b, fileUtilInst)
	if err != nil {
		log.Errorf("Cannot convert bootstrap config to yaml. %v", err)
		return "", err
	}
	return configYaml, nil
}
