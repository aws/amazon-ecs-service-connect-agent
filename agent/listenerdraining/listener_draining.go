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

package listenerdraining

import (
	"fmt"
	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

const (
	inboundOnlyQueryKey = "inboundonly"
)

type EnvoyListenerDrainHandler struct {
	AgentConfig     config.AgentConfig
	Limiter         *rate.Limiter
	queryParameters url.Values
}

func (envoyListenerDrainHandler *EnvoyListenerDrainHandler) HandleDraining(responseWriter http.ResponseWriter, request *http.Request) {
	log.Info("Received request to drain listener connections.")

	if !envoyListenerDrainHandler.Limiter.Allow() {
		http.Error(responseWriter, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}

	// Validate the request and query parameters before calling Envoy drain endpoint.
	if queryParams, err := validateDrainingRequest(request); err != nil {
		http.Error(responseWriter, err.Error(), http.StatusBadRequest)
		return
	} else {
		envoyListenerDrainHandler.queryParameters = *queryParams
	}

	envoyListenerDrainUrl := envoyListenerDrainHandler.getEnvoyListenerDrainUrl()
	log.Debugf("Url to Envoy Listener Drain Endpoint: %s", envoyListenerDrainUrl)

	// Send request to Envoy Drain endpoint
	httpClient, err := client.CreateRetryableHttpClientForEnvoyServer(envoyListenerDrainHandler.AgentConfig)
	if err != nil {
		log.Errorf("Failed to create Retryable Http Client: %v", err)
		http.Error(responseWriter, "Unable to drain Envoy listeners", http.StatusInternalServerError)
		return
	}
	drainRequest, err := client.CreateRetryableAgentRequest(http.MethodPost, envoyListenerDrainUrl, nil)
	if err != nil {
		log.Errorf("Unable to create drain request to Envoy: %v", err)
		http.Error(responseWriter, "Unable to drain Envoy listeners", http.StatusInternalServerError)
		return
	}

	drainResponse, err := httpClient.Do(drainRequest)
	if err != nil {
		log.Errorf("Unable to reach Envoy Admin port: %v", err)
		http.Error(responseWriter, "Unable to drain Envoy listeners", http.StatusInternalServerError)
		return
	}
	if drainResponse == nil {
		responseWriter.WriteHeader(http.StatusNoContent)
		log.Debug("Empty response from Envoy drain endpoint.")
		return
	}

	defer drainResponse.Body.Close()

	if drainResponse.StatusCode != http.StatusOK {
		log.Errorf("Draining Envoy listeners failed [response %d - %s]",
			drainResponse.StatusCode, drainResponse.Status)
		http.Error(responseWriter, "Unable to drain Envoy listeners", http.StatusInternalServerError)
		return
	}

	log.Infof("Initiated Envoy inbound listener draining [response %d - %s]", drainResponse.StatusCode, drainResponse.Status)

	responseBody, err := ioutil.ReadAll(drainResponse.Body)
	if err != nil {
		log.Warnf("Unable to read drain response from Envoy: %v", err)
		// We did get a 200 back though
		responseWriter.WriteHeader(http.StatusOK)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)
	_, err = responseWriter.Write(responseBody)
	if err != nil {
		log.Errorf("Error while writing response: %s", err)
	}
}

// TODO: Create common validation handler to validate all http requests before passing them to corresponding request handlers
// validateDrainingRequest validates the given http.Request and extracts the queryParameters on success.
func validateDrainingRequest(request *http.Request) (*url.Values, error) {
	// Verify that the request is a POST request
	if request.Method != http.MethodPost {
		errorMsg := fmt.Sprintf("Invalid method [%s] in request", request.Method)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	// Verify that no message body is present
	if request.ContentLength > 0 {
		errorMsg := fmt.Sprintf("Unexpected content in request. Body size [%d]", request.ContentLength)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	// Verify the parameters supplied
	queryParameters, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		errorMsg := fmt.Sprintf("Unable to parse queries in URL: %s", err)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}
	log.Debugf("Query Values: %v", queryParameters)

	queryParameterCount := len(queryParameters)
	if queryParameterCount != 1 {
		errorMsg := fmt.Sprintf("Unexpected number of query parameters specified in request: [%d]", queryParameterCount)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	if _, ok := queryParameters[inboundOnlyQueryKey]; !ok {
		errorMsg := fmt.Sprintf("Unexpected query parameters specified in request [%v]", queryParameters)
		log.Debug(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	return &queryParameters, nil
}

// getEnvoyListenerDrainUrl generates the full http url to call Envoy Listener Drain API.
func (envoyListenerDrainHandler *EnvoyListenerDrainHandler) getEnvoyListenerDrainUrl() string {
	return fmt.Sprintf("%s://%s:%d%s?%s",
		envoyListenerDrainHandler.AgentConfig.EnvoyServerScheme,
		envoyListenerDrainHandler.AgentConfig.EnvoyServerHostName,
		envoyListenerDrainHandler.AgentConfig.EnvoyServerAdminPort,
		envoyListenerDrainHandler.AgentConfig.EnvoyListenerDrainUrl,
		inboundOnlyQueryKey)
}
