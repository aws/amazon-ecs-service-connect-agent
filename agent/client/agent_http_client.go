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

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	"github.com/hashicorp/go-retryablehttp"
	log "github.com/sirupsen/logrus"
)

const (
	HTTP_CLIENT_TIMEOUT        = 250 * time.Millisecond
	HTTP_CLIENT_RETRY_MAX      = 3
	HTTP_CLIENT_RETRY_WAIT_MIN = 100 * time.Millisecond
	HTTP_CLIENT_RETRY_WAIT_MAX = 1000 * time.Millisecond
)

func CreateDefaultRetryableHttpClient() *retryablehttp.Client {
	// Default TCP retryable httpClient
	httpClient := retryablehttp.NewClient()
	httpClient.HTTPClient.Timeout = HTTP_CLIENT_TIMEOUT
	httpClient.RetryMax = HTTP_CLIENT_RETRY_MAX
	httpClient.RetryWaitMin = HTTP_CLIENT_RETRY_WAIT_MIN
	httpClient.RetryWaitMax = HTTP_CLIENT_RETRY_WAIT_MAX
	httpClient.Logger = nil // If this is not set retryablehttp client will write DEBUG logs on GET calls
	httpClient.ErrorHandler = RetryErrorHandler
	return httpClient
}

func CreateRetryableHttpClientForEnvoyServer(agentConfig config.AgentConfig) (*retryablehttp.Client, error) {
	// create UDS or TCP retryable httpClient for envoy server. For UDS, bind the client to Envoy Admin UDS path
	var retryableClient *retryablehttp.Client
	switch agentConfig.EnvoyAdminMode {
	case config.UDS:
		if _, err := os.Stat(agentConfig.EnvoyServerAdminUdsPath); os.IsNotExist(err) {
			msg := fmt.Sprintf("UDS path [%s] for Retryable HttpClient does not exist: %v",
				agentConfig.EnvoyServerAdminUdsPath, err)
			log.Error(msg)
			return nil, fmt.Errorf(msg)
		}
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial(config.NETWORK_SOCKET_UNIX, agentConfig.EnvoyServerAdminUdsPath)
				},
			},
		}
		httpClient.Timeout = HTTP_CLIENT_TIMEOUT
		retryableClient = CreateDefaultRetryableHttpClient()
		retryableClient.HTTPClient = httpClient
	default:
		retryableClient = CreateDefaultRetryableHttpClient()
	}
	return retryableClient, nil
}

func CreateDefaultHttpClientForEnvoyServer(agentConfig config.AgentConfig) (*http.Client, error) {
	// create UDS or TCP httpClient for envoy server. For UDS, bind the client to Envoy Admin UDS path.
	// This is similar to the previous func CreateRetryableHttpClientForEnvoyServer but without any retry.
	switch agentConfig.EnvoyAdminMode {
	case config.UDS:
		if _, err := os.Stat(agentConfig.EnvoyServerAdminUdsPath); os.IsNotExist(err) {
			msg := fmt.Sprintf("UDS path [%s] for HttpClient does not exist: %v",
				agentConfig.EnvoyServerAdminUdsPath, err)
			log.Error(msg)
			return nil, fmt.Errorf(msg)
		}
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial(config.NETWORK_SOCKET_UNIX, agentConfig.EnvoyServerAdminUdsPath)
				},
			},
			Timeout: HTTP_CLIENT_TIMEOUT,
		}, nil
	default:
		return CreateDefaultHttpClient(), nil
	}
}

func CreateHttpClientForAgentServer(agentConfig config.AgentConfig) (*http.Client, error) {
	_, err := os.Stat(agentConfig.AgentAdminUdsPath)
	if err != nil {
		return nil, fmt.Errorf("socket path [%s] does not exist", agentConfig.AgentAdminUdsPath)
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(config.NETWORK_SOCKET_UNIX, agentConfig.AgentAdminUdsPath)
			},
		},
	}, nil
}

func CreateDefaultHttpClient() *http.Client {
	return &http.Client{Timeout: HTTP_CLIENT_TIMEOUT}
}

func CreateRetryableAgentRequest(method, requestUrl string, rawBody interface{}) (*retryablehttp.Request, error) {
	request, err := retryablehttp.NewRequest(method, requestUrl, rawBody)
	if err != nil {
		msg := fmt.Sprintf("unable to create new retryablehttp request: %v, requestUrl: %s", err, requestUrl)
		log.Error(msg)
		return nil, fmt.Errorf(msg)
	}
	request.Header.Add("Connection", "close")
	request.Header.Add("User-Agent", config.APPNET_USER_AGENT)
	return request, nil
}

func CreateStandardAgentHttpRequest(method, requestUrl string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, requestUrl, body)
	if err != nil {
		msg := fmt.Sprintf("unable to create new http request: %v, requestUrl: %s", err, requestUrl)
		log.Error(msg)
		return nil, fmt.Errorf(msg)
	}
	request.Header.Add("Connection", "close")
	request.Header.Add("User-Agent", config.APPNET_USER_AGENT)
	return request, nil
}

func RetryErrorHandler(resp *http.Response, err error, attempt int) (retryResponse *http.Response, retryError error) {
	if resp != nil && resp.StatusCode < 600 && resp.StatusCode >= 100 {
		retryError = fmt.Errorf("giving up after %d attempt(s), error: %v, status: %v", attempt, err, resp.Status)
	} else {
		retryError = fmt.Errorf("giving up after %d attempt(s), error: %v", attempt, err)
	}
	retryResponse = resp
	return
}
