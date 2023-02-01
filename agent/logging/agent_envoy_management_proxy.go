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

package logging

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"

	log "github.com/sirupsen/logrus"
	rate "golang.org/x/time/rate"
)

const (
	QUERY_KEY = "level"
)

type EnvoyLoggingHandler struct {
	AgentConfig     config.AgentConfig
	Limiter         *rate.Limiter
	request         *http.Request
	response        *http.ResponseWriter
	queryParameters url.Values
	pendingReset    bool
}

func (envoyHandler *EnvoyLoggingHandler) changeLoggerLevels(logLevel string) (string, error) {

	envoyLoggingUrl := fmt.Sprintf("%s://%s:%d%s?level=%s",
		envoyHandler.AgentConfig.EnvoyServerScheme,
		envoyHandler.AgentConfig.EnvoyServerHostName,
		envoyHandler.AgentConfig.EnvoyServerAdminPort,
		envoyHandler.AgentConfig.EnvoyLoggingUrl,
		logLevel)
	log.Debugf("Handler Using Envoy url for logging change [%s]\n", envoyLoggingUrl)

	httpClient, err := client.CreateRetryableHttpClientForEnvoyServer(envoyHandler.AgentConfig)
	if err != nil {
		log.Errorf("Unable to create Retryable Http Client: %v", err)
		return "", err
	}
	req, _ := client.CreateRetryableAgentRequest(http.MethodPost, envoyLoggingUrl, nil)
	res, err := httpClient.Do(req)
	if err != nil {
		log.Errorf("Unable to update the logging level: %s", err)
		return "", err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Errorf("Setting the new logging level failed [response %d - %s]",
			res.StatusCode, res.Status)
		return "", errors.New("unable to set logging level")
	}

	// Parse the response and confirm that there is only one level set for all modules
	responseData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Warnf("Unable to read response from Envoy: %s", err)
		// We did get a 200 back so ¯\_(ツ)_/¯
	}

	responseContent := string(responseData)
	if len(responseContent) > 0 {
		var statusCodes map[string]int = make(map[string]int)
		for _, line := range strings.Split(responseContent, "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 0 && !strings.HasPrefix(line, "active loggers") {
				module_level := strings.Split(line, ":")
				log.Debugf("Module [%v]\n", module_level)
				statusCodes[strings.TrimSpace(module_level[1])]++
			}
		}

		if statusCodes[logLevel] == 0 {
			log.Warnf("All log levels were not able to be modified to [%s]", logLevel)
		}
	}
	return envoyHandler.AgentConfig.EnvoyLogLevel, nil
}

func (envoyHandler *EnvoyLoggingHandler) validateEnableLoggingRequest() bool {

	// Verify that the request is a POST
	if envoyHandler.request.Method != http.MethodPost {
		log.Debugf("Invalid method [%v] in request", envoyHandler.request.Method)
		http.Error(*envoyHandler.response,
			"Only POST requests are supported", http.StatusBadRequest)
		return false
	}

	// Verify that no message body is present
	if envoyHandler.request.ContentLength > 0 {
		log.Debugf("Unexpected content in request.  Body size [%d]",
			envoyHandler.request.ContentLength)

		http.Error(*envoyHandler.response, "Invalid request", http.StatusBadRequest)
		return false
	}

	// Verify the parameters supplied
	values, err := url.ParseQuery(envoyHandler.request.URL.RawQuery)
	if err != nil {
		log.Debug("Unable to parse queries in URL")
		http.Error(*envoyHandler.response, "Invalid request", http.StatusBadRequest)
		return false
	}
	queryParameterCount := len(values)
	log.Debugf("Query Values: %v", values)

	if queryParameterCount != 1 || values.Get(QUERY_KEY) == "" {
		log.Debugf("Unexpected query parameters specified in request [%v]",
			values)
		http.Error(*envoyHandler.response, "Invalid request", http.StatusBadRequest)
		return false
	}

	envoyHandler.queryParameters = values

	return true
}

func (envoyHandler *EnvoyLoggingHandler) resetLogLevel() {
	// If this is already armed, then do nothing
	if envoyHandler.pendingReset {
		return
	}

	go func() {
		logLevel := envoyHandler.AgentConfig.EnvoyLogLevel
		interval := envoyHandler.AgentConfig.AgentLoglevelReset

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		select {
		case <-ticker.C:
			log.Infof("Resetting Envoy logging level to [%s]", logLevel)
			envoyHandler.pendingReset = false
			envoyHandler.changeLoggerLevels(logLevel)
			return
		}
	}()

	envoyHandler.pendingReset = true
}

func (envoyHandler *EnvoyLoggingHandler) LoggingHandler(response http.ResponseWriter, request *http.Request) {

	if !envoyHandler.Limiter.Allow() {
		responseCode := http.StatusTooManyRequests
		http.Error(response, http.StatusText(responseCode), responseCode)
		return
	}

	if envoyHandler.pendingReset {
		log.Debugf("There is a pending reset to log level %s",
			envoyHandler.AgentConfig.EnvoyLogLevel)

		// This is a no-op until that pending reset happens
		responseCode := http.StatusNotModified
		http.Error(response, http.StatusText(responseCode), responseCode)
		return
	}

	envoyHandler.request = request
	envoyHandler.response = &response

	if !envoyHandler.validateEnableLoggingRequest() {
		return
	}

	// Examine the queryParameters, sanitize, and then operate
	logLevel := envoyHandler.queryParameters.Get(QUERY_KEY)

	if len(logLevel) > 5 {
		http.Error(*envoyHandler.response, "Invalid log level specified", http.StatusBadRequest)
		return
	}

	if logLevel == envoyHandler.AgentConfig.EnvoyLogLevel {
		// This is a no-op also.  snapshot log level is the desired log level
		responseCode := http.StatusNotModified
		http.Error(response, http.StatusText(responseCode), responseCode)
		return
	}

	previousLogLevel, err := envoyHandler.changeLoggerLevels(logLevel)
	var responseBody string
	if err != nil {
		responseBody = fmt.Sprintf("Unable to set logging level to [%s]\n", logLevel)

		response.WriteHeader(http.StatusInternalServerError)
	} else {
		responseBody = fmt.Sprintf("Setting logging level from [%s] to [%s]\n",
			previousLogLevel, logLevel)

		response.WriteHeader(http.StatusOK)

		// TOOD: Need to cancel the reset if the process restarts after
		// 		   the loglevel has changed.
		envoyHandler.resetLogLevel()
	}

	log.Debug(responseBody)
	io.WriteString(response, responseBody)
}
