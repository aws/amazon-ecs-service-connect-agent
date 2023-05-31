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

package stats

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/internal/netlistenertest"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func buildHandlerWithSnapshotter(agentConfig config.AgentConfig, snapshotter *Snapshotter) EnvoyPrometheusStatsHandler {
	return EnvoyPrometheusStatsHandler{
		AgentConfig: agentConfig,
		Limiter:     rate.NewLimiter(config.TPS_LIMIT, config.BURST_TPS_LIMIT),
		Snapshotter: snapshotter,
	}
}

func buildHandler(agentConfig config.AgentConfig) EnvoyPrometheusStatsHandler {
	return EnvoyPrometheusStatsHandler{
		AgentConfig: agentConfig,
		Limiter:     rate.NewLimiter(config.TPS_LIMIT, config.BURST_TPS_LIMIT),
	}
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Success(t *testing.T) {
	// Setup an http server that serves stats request
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnvoyAdminMode = config.TCP

	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	sampleStatsOutput := "This is a sample stats output"
	envoy := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, sampleStatsOutput)
	}))
	defer envoy.Close()

	// Create a new listener to listen on Envoy Admin Port
	var envoyListenCtx netlistenertest.ListenContext
	err := envoyListenCtx.CreateEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)
	defer envoyListenCtx.Close()

	// Close the httptest listener as it listens on port 80 by default
	err = envoy.Listener.Close()
	assert.Nil(t, err)

	// Attach the new listener to the httptest server
	envoy.Listener = *envoyListenCtx.Listener
	envoy.Start()

	envoyStatsHandler := buildHandler(agentConfig)
	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()
	res, _ := http.Get(statsServer.URL)

	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	defer res.Body.Close()
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, sampleStatsOutput, string(resBody))
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Failure_Envoy_Internal_Error(t *testing.T) {
	// Setup an http server that serves stats request
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnvoyAdminMode = config.TCP
	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	envoy := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "dummy error", http.StatusBadGateway)
	}))
	defer envoy.Close()
	// Create a new listener to listen on Envoy Admin Port
	var envoyListenCtx netlistenertest.ListenContext
	err := envoyListenCtx.CreateEnvoyAdminListener(&agentConfig)
	assert.Nil(t, err)
	defer envoyListenCtx.Close()

	// Close the httptest listener as it listens on port 80 by default
	err = envoy.Listener.Close()
	assert.Nil(t, err)

	// Attach the new listener to the httptest server
	envoy.Listener = *envoyListenCtx.Listener
	envoy.Start()

	envoyStatsHandler := buildHandler(agentConfig)
	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()
	res, err := http.Get(statsServer.URL)

	assert.NotNil(t, res)
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)

	defer res.Body.Close()
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Success_QueryParameter_Usedonly(t *testing.T) {
	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	sampleStatsOutput := "usedonly param enabled."
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		queryParameters, _ := url.ParseQuery(request.URL.RawQuery)
		if queryParameters.Has(usedOnlyQueryKey) {
			io.WriteString(writer, sampleStatsOutput)
		}
	}))

	// Setup an http server that serves stats request
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnvoyAdminMode = config.TCP
	envoyStatsHandler := buildHandler(agentConfig)
	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()
	requestUrl := fmt.Sprintf("%s?%s", statsServer.URL, usedOnlyQueryKey)
	res, err := http.Get(requestUrl)

	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	defer res.Body.Close()
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	assert.Equal(t, sampleStatsOutput, string(resBody))
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Failure_QueryParameter_Unsupported_Param(t *testing.T) {
	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	sampleStatsOutput := "usedonly param enabled."
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		queryParameters, _ := url.ParseQuery(request.URL.RawQuery)
		if queryParameters.Has(usedOnlyQueryKey) {
			io.WriteString(writer, sampleStatsOutput)
		}
	}))

	// Setup an http server that serves stats request
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	agentConfig.EnvoyAdminMode = config.TCP
	envoyStatsHandler := buildHandler(agentConfig)
	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()
	randomParam := "unsupported_random_param"
	requestUrl := fmt.Sprintf("%s?%s", statsServer.URL, randomParam)
	res, _ := http.Get(requestUrl)

	assert.NotNil(t, res)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)

	defer res.Body.Close()
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	errorMsg := fmt.Sprintf("unsupported query parameter: %s\n", randomParam)
	assert.Equal(t, errorMsg, string(resBody))
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Success_QueryParameter_Metrics_Filtering_and_Sorting(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", config.ENVOY_ADMIN_MODE_DEFAULT)
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	// 1. Ideally the sampleStatsOutput from Envoy stats endpoint should already be sorted, but we are testing our sort
	// logic below, so the "envoy_appmesh_GrpcRequestCount" metric was placed in a reversed order which is expected to
	// be sorted later by the HandleStats function.
	// 2. We should also see the "envoy_cluster_default_total_match_count" being filtered out.
	sampleStatsOutput := "# TYPE envoy_appmesh_GrpcRequestCount counter\n" +
		"envoy_appmesh_GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n" +
		"envoy_appmesh_GrpcRequestCount{Mesh=\"howto-k8s-http1\",VirtualNode=\"client_howto-k8s-http1\"} 0\n" +
		"# TYPE envoy_appmesh_NewConnectionCount counter\n" +
		"envoy_appmesh_NewConnectionCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n" +
		"# TYPE envoy_cluster_default_total_match_count counter\n" +
		"envoy_cluster_default_total_match_count{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\",envoy_cluster_name=\"cds_egress_howto-k8s-http2_amazonaws\"} 0\n"
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, sampleStatsOutput)
	}))

	// Setup an http server that serves stats request
	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	envoyStatsHandler := buildHandler(agentConfig)
	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()
	filterParam := fmt.Sprintf("%s=%s", filterQueryKey, QuerySet[filterQueryKey])
	requestUrl := fmt.Sprintf("%s?%s", statsServer.URL, filterParam)
	res, err := http.Get(requestUrl)

	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	defer res.Body.Close()
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	// Expect the filtered metrics
	expectedResponse := "\n# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http1\",VirtualNode=\"client_howto-k8s-http1\"} 0\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n" +
		"\n# TYPE NewConnectionCount counter\n" +
		"NewConnectionCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n"
	assert.Equal(t, expectedResponse, string(resBody))
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Success_QueryParameter_Delta_SingleSnapshot(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", config.ENVOY_ADMIN_MODE_DEFAULT)
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	result := 0
	deltaValue := 0
	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sampleStatsOutput := fmt.Sprintf("# TYPE envoy_appmesh_GrpcRequestCount counter\n"+
			"envoy_appmesh_GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} %d\n", result)
		io.WriteString(writer, sampleStatsOutput)
		result += deltaValue
	}))

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	var snapshotter Snapshotter
	envoyStatsHandler := buildHandlerWithSnapshotter(agentConfig, &snapshotter)
	assert.Nil(t, snapshotter.Delta)

	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())

	// Setup an http server that serves stats request
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()

	// Manually Snapshot one time to computeDelta
	statsUrl := getEnvoyStatsUrl(&envoyStatsHandler.AgentConfig, "")
	snapshotter.HttpClient = client.CreateDefaultRetryableHttpClient()
	snapshotter.HttpRequest, err = client.CreateRetryableAgentRequest(http.MethodGet, statsUrl, nil)
	assert.NoError(t, err)
	// Make one snapshot, then call computeDelta
	snapshotter.makeSnapshot()

	filterParam := fmt.Sprintf("%s=%s", filterQueryKey, QuerySet[filterQueryKey])
	requestUrl := fmt.Sprintf("%s?%s&%s&%s", statsServer.URL, filterParam, usedOnlyQueryKey, deltaQueryKey)

	// Expecting Delta value equals to 0 and Delta object equals to the very first snapshot
	assert.NotNil(t, snapshotter.Delta)
	assert.Equal(t, snapshotter.Delta, snapshotter.Snapshot)
	res, err := http.Get(requestUrl)
	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	expectedResponse := fmt.Sprintf("\n# TYPE GrpcRequestCount counter\n"+
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} %d\n", deltaValue)
	assert.Equal(t, expectedResponse, string(resBody))
	res.Body.Close()
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Success_QueryParameter_Delta(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", config.ENVOY_ADMIN_MODE_DEFAULT)
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	result := 0
	deltaValue := 5
	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sampleStatsOutput := fmt.Sprintf("# TYPE envoy_appmesh_GrpcRequestCount counter\n"+
			"envoy_appmesh_GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} %d\n", result)
		io.WriteString(writer, sampleStatsOutput)
		result += deltaValue
	}))

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	var snapshotter Snapshotter
	envoyStatsHandler := buildHandlerWithSnapshotter(agentConfig, &snapshotter)

	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())

	// Setup an http server that serves stats request
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()

	// Manually Snapshot two times to computeDelta
	statsUrl := getEnvoyStatsUrl(&envoyStatsHandler.AgentConfig, "")
	snapshotter.HttpClient = client.CreateDefaultRetryableHttpClient()
	snapshotter.HttpRequest, err = client.CreateRetryableAgentRequest(http.MethodGet, statsUrl, nil)
	assert.NoError(t, err)
	// Make two snapshots, then compute
	snapshotter.makeSnapshot()
	snapshotter.makeSnapshot()

	filterParam := fmt.Sprintf("%s=%s", filterQueryKey, QuerySet[filterQueryKey])
	requestUrl := fmt.Sprintf("%s?%s&%s&%s", statsServer.URL, filterParam, usedOnlyQueryKey, deltaQueryKey)

	// Expecting Delta = 5
	res, err := http.Get(requestUrl)
	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	expectedResponse := fmt.Sprintf("\n# TYPE GrpcRequestCount counter\n"+
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} %d\n", deltaValue)
	assert.Equal(t, expectedResponse, string(resBody))
	res.Body.Close()
}

func TestEnvoyPrometheusStatsHandler_HandleStats_Success_QueryParameter_Delta_NewMetrics(t *testing.T) {
	os.Setenv("ENVOY_ADMIN_MODE", config.ENVOY_ADMIN_MODE_DEFAULT)
	defer os.Unsetenv("ENVOY_ADMIN_MODE")

	metricVerTagValue := 0
	sampleStatsOutput := "# TYPE envoy_appmesh_GrpcRequestCount counter\n"
	// Mock an Envoy server since we are not spawning an Envoy for this unit test
	envoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		metricVerTagValue += 1
		sampleStatsOutput += fmt.Sprintf("envoy_appmesh_GrpcRequestCount{MetricVer=\"v%d\",VirtualNode=\"client_howto-k8s-http2\"} 5\n", metricVerTagValue)
		io.WriteString(writer, sampleStatsOutput)
	}))

	var agentConfig config.AgentConfig
	agentConfig.SetDefaults()
	var snapshotter Snapshotter
	envoyStatsHandler := buildHandlerWithSnapshotter(agentConfig, &snapshotter)

	// Update EnvoyServer info to honor the mock Envoy server
	envoyUrl, err := url.Parse(envoy.URL)
	assert.NoError(t, err)
	envoyStatsHandler.AgentConfig.EnvoyServerScheme = envoyUrl.Scheme
	envoyStatsHandler.AgentConfig.EnvoyServerHostName = envoyUrl.Hostname()
	envoyStatsHandler.AgentConfig.EnvoyServerAdminPort, _ = strconv.Atoi(envoyUrl.Port())

	// Setup an http server that serves stats request
	statsServer := httptest.NewServer(http.HandlerFunc(envoyStatsHandler.HandleStats))
	defer statsServer.Close()

	// Manually Snapshot two times to computeDelta
	statsUrl := getEnvoyStatsUrl(&envoyStatsHandler.AgentConfig, "")
	snapshotter.HttpClient = client.CreateDefaultRetryableHttpClient()
	snapshotter.HttpRequest, err = client.CreateRetryableAgentRequest(http.MethodGet, statsUrl, nil)
	assert.NoError(t, err)
	// Make two snapshots, then compute, here making snapshot would indirectly call the Envoy stats handler
	snapshotter.makeSnapshot()
	snapshotter.makeSnapshot()

	filterParam := fmt.Sprintf("%s=%s", filterQueryKey, QuerySet[filterQueryKey])
	requestUrl := fmt.Sprintf("%s?%s&%s&%s", statsServer.URL, filterParam, usedOnlyQueryKey, deltaQueryKey)

	// Expecting new Metric Entry
	res, err := http.Get(requestUrl)
	assert.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	resBody, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err)
	expectedResponse := "\n# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{MetricVer=\"v1\",VirtualNode=\"client_howto-k8s-http2\"} 0\n" +
		"GrpcRequestCount{MetricVer=\"v2\",VirtualNode=\"client_howto-k8s-http2\"} 5\n"
	assert.Equal(t, expectedResponse, string(resBody))
	res.Body.Close()
}

func TestParsePrometheusStats(t *testing.T) {
	statsInput := []byte("# TYPE GrpcRequestCount counter\n" +
		"GrpcRequestCount{Mesh=\"howto-k8s-http2\",VirtualNode=\"client_howto-k8s-http2\"} 0\n")
	metricFamilies, err := parsePrometheusStats(statsInput)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(metricFamilies))
	name := "GrpcRequestCount"
	metricFamily, ok := metricFamilies[name]
	assert.True(t, ok)
	assert.Equal(t, name, metricFamily.GetName())
	assert.Equal(t, 1, len(metricFamily.Metric))
	assert.NotNil(t, metricFamily.Metric[0].Counter)
	assert.Equal(t, float64(0), metricFamily.Metric[0].Counter.GetValue())
}

func TestEnvoyPrometheusStatsHandler_ValidateGetStatsRequest_Bad_Request(t *testing.T) {

	mockServerUrl := "mock_server_url"

	// Case 1: Create a POST request to Stats Endpoint
	filterParam := fmt.Sprintf("%s=%s", filterQueryKey, QuerySet[filterQueryKey])
	requestUrl := fmt.Sprintf("%s?%s", mockServerUrl, filterParam)
	request, _ := client.CreateStandardAgentHttpRequest(http.MethodPost, requestUrl, nil)
	params, err := validateGetStatsRequest(request)
	assert.Error(t, err)
	expectedError := fmt.Sprintf("invalid method [%s] in request", http.MethodPost)
	assert.Nil(t, params)
	assert.Equal(t, expectedError, err.Error())

	// Case 2: Request with request.ContentLength > 0
	request, err = client.CreateStandardAgentHttpRequest(http.MethodGet, requestUrl, bytes.NewBuffer([]byte("random body")))
	assert.NoError(t, err)
	_, err = validateGetStatsRequest(request)
	expectedError = fmt.Sprintf("unexpected content in request. Body size [%d]", request.ContentLength)

	assert.Error(t, err)
	assert.Equal(t, expectedError, err.Error())

	// Case 3: Request with unsupported filter value
	randomFilterValue := "random"
	filterParam = fmt.Sprintf("%s=%s", filterQueryKey, randomFilterValue)
	requestUrl = fmt.Sprintf("%s?%s", mockServerUrl, filterParam)
	request, _ = client.CreateStandardAgentHttpRequest(http.MethodGet, requestUrl, nil)
	_, err = validateGetStatsRequest(request)

	assert.Error(t, err)
	expectedError = fmt.Sprintf("unsupported query value for parameter %s: %s, usage: %s", filterQueryKey, randomFilterValue, filterQueryUsage)
	assert.Equal(t, expectedError, err.Error())

	// Case 4: "usedonly" or "filter=metrics_extension" query parameter was not provided when "delta" is used.
	requestUrl = fmt.Sprintf("%s?%s", mockServerUrl, deltaQueryKey)
	request, _ = client.CreateStandardAgentHttpRequest(http.MethodGet, requestUrl, nil)
	_, err = validateGetStatsRequest(request)

	assert.Error(t, err)
	expectedError = fmt.Sprintf("when delta is enabled, both %s and %s query parameters are required", usedOnlyQueryKey, filterQueryKey)
	assert.Equal(t, expectedError, err.Error())
}
