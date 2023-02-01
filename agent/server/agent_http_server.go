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

package server

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

type HandlerFunction func(http.ResponseWriter, *http.Request)
type HandlerSpec map[string]HandlerFunction

func StartHttpServer(agentConfig config.AgentConfig, handlers HandlerSpec, messageSources *messagesources.MessageSources) {
	if agentConfig.AgentAdminMode == config.UDS {
		// When starting a UDS HttpServer, UDS path needs to be removed first if it exists,
		// or there will be 'address already in use' error
		if err := os.Remove(agentConfig.AgentAdminUdsPath); err != nil && !os.IsNotExist(err) {
			log.Fatalf("Failed to remove Agent Admin UDS path:[%s], %v", agentConfig.AgentAdminUdsPath, err)
			messageSources.SetAgentExit()
			return
		}
	}
	// Register all configured handlers
	router := mux.NewRouter()
	for path, function := range handlers {
		if function == nil {
			log.Warnf("Handler for path [%s] is nil.  Not regstering it", path)
			continue
		}
		router.HandleFunc(path, function)
	}

	var listener net.Listener
	var err error
	switch agentConfig.AgentAdminMode {
	case config.UDS:
		listener, err = net.Listen(config.NETWORK_SOCKET_UNIX, agentConfig.AgentAdminUdsPath)
		if err != nil {
			log.Fatalf("Error starting the Agent HTTP server on Uds path, exiting agent: %v", err)
			messageSources.SetAgentExit()
			return
		}
	case config.TCP:
		tcpAddr := fmt.Sprintf("%s:%d", agentConfig.AgentHttpAddress, agentConfig.AgentHttpPort)
		listener, err = net.Listen(config.NETWORK_SOCKET_TCP, tcpAddr)
		if err != nil {
			log.Fatalf("Unable to start a listener on TCP Address, exiting agent: %v", err)
			messageSources.SetAgentExit()
			return
		}
	}
	log.Infof("Server started, %s", listener.Addr().String())
	if err := http.Serve(listener, router); err != nil {
		log.Fatalf("Error starting the Agents HTTP server, exiting agent: %v", err)
		messageSources.SetAgentExit()
		return
	}
}
