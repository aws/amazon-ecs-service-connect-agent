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

package netlistenertest

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	log "github.com/sirupsen/logrus"
)

type ListenContext struct {
	Port     int
	UdsPath  string
	Listener *net.Listener
}

func (ctx *ListenContext) Close() error {
	var err error = nil
	if ctx.Listener != nil {
		err = (*ctx.Listener).Close()
		if err != nil {
			log.Debugf("Cannot close listener. %v", err)
		}
	}
	if ctx.UdsPath != "" {
		err = os.Remove(ctx.UdsPath)
		if err != nil {
			log.Debugf("Cannot remove UDS path. %v", err)
		}
	}
	return err
}

func (ctx *ListenContext) GetUdsListener() error {
	tmpFile, err := ioutil.TempFile(os.TempDir(), "envoy_admin_test_*.sock")
	if err != nil {
		log.Debugf("Cannot create Unix Domain Socket file. %v", err)
		return err
	}
	udsPath := tmpFile.Name()
	if err := os.Remove(udsPath); err != nil {
		log.Debugf("Cannot remove uds file before starting a uds listener: %v", err)
		return err
	}
	if listener, err := net.Listen(config.NETWORK_SOCKET_UNIX, udsPath); err == nil {
		ctx.Listener = &listener
		ctx.UdsPath = udsPath
		log.Debugf("Created Listener: %s", listener.Addr().String())
		return nil
	}
	log.Debugf("Failed to create listener on uds:[%s], %v", udsPath, err)
	return err
}

func (ctx *ListenContext) GetPortListener() error {

	const MAX_ATTEMPTS int = 10
	var index int = 0
	var port int = config.ENVOY_ADMIN_PORT_DEFAULT + 4

	for {
		if listener, err := net.Listen(config.NETWORK_SOCKET_TCP, fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			ctx.Port = port
			ctx.Listener = &listener
			log.Debugf("Created Listener: %s", listener.Addr().String())
			return nil
		}

		if index >= MAX_ATTEMPTS {
			msg := fmt.Sprintf("Unable to find a free port in [%d] tries", index)
			log.Error(msg)
			return fmt.Errorf(msg)
		}

		port += 1
		index += 1
	}
}

func (ctx *ListenContext) CreateEnvoyAdminListener(agentConfig *config.AgentConfig) error {
	switch agentConfig.EnvoyAdminMode {
	case config.UDS:
		if err := ctx.GetUdsListener(); err != nil {
			return err
		}
		agentConfig.EnvoyServerAdminUdsPath = ctx.UdsPath
	default:
		if err := ctx.GetPortListener(); err != nil {
			return err
		}
		agentConfig.EnvoyServerAdminPort = ctx.Port
	}
	return nil
}

func (ctx *ListenContext) CreateLocalRelayEnvoyAdminListener(agentConfig *config.AgentConfig) error {
	if err := ctx.GetPortListener(); err != nil {
		return err
	}
	agentConfig.LocalRelayEnvoyAdminPort = ctx.Port
	return nil
}
