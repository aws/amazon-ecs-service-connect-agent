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

package messagesources

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type MessageSources struct {
	processAlive               chan bool
	shouldTerminateProcess     chan bool
	agentExit                  chan struct{}
	BlockingEnvoyStatusTrigger chan struct{}
	lastPidCheckChannel        chan int64
	lastProcessStatus          bool
	terminateProcess           bool
	checkStatus                bool
	forkedPid                  int
	lastPidCheck               int64
	processRestartCount        int
}

func (messageSources *MessageSources) SetupChannels() {
	// For monitoring Envoy process
	messageSources.processAlive = make(chan bool, 1)
	messageSources.shouldTerminateProcess = make(chan bool, 1)
	messageSources.agentExit = make(chan struct{}, 1)
	messageSources.BlockingEnvoyStatusTrigger = make(chan struct{}, 1)
	messageSources.lastPidCheckChannel = make(chan int64, 1)
	messageSources.lastProcessStatus = false
	messageSources.terminateProcess = false
	messageSources.checkStatus = false
	messageSources.forkedPid = -1
	messageSources.lastPidCheck = 0
	messageSources.processRestartCount = 0
}

func (messageSources *MessageSources) readChannels() {

	start := time.Now()

	select {
	case messageSources.lastProcessStatus = <-messageSources.processAlive:
	default:
		log.Trace("No activity on processAlive")
	}

	select {
	case messageSources.terminateProcess = <-messageSources.shouldTerminateProcess:
	default:
		log.Trace("No activity on shouldTerminateProcess")
	}

	select {
	case messageSources.lastPidCheck = <-messageSources.lastPidCheckChannel:
	default:
		log.Trace("No activity on lastPidCheckChannel")
	}

	// We won't read the following channels since we want them to block
	// messageSources.agentExit
	// messageSources.BlockingEnvoyStatusTrigger

	log.Tracef("Channel read took [%d us]", time.Since(start).Microseconds())
}

func (messageSources *MessageSources) SetProcessState(state bool) {
	select {
	case messageSources.processAlive <- state:
		// no-op
	default:
		// no-op
	}
}

func (messageSources *MessageSources) SetTerminateProcess(state bool) {
	select {
	case messageSources.shouldTerminateProcess <- state:
		// no-op
	default:
		// no-op
	}
}

func (messageSources *MessageSources) SetAgentExit() {
	select {
	case messageSources.agentExit <- struct{}{}:
		// no-op
	default:
		// no-op
	}
}

func (messageSources *MessageSources) SetProcessRestartCount(restartCount int) {
	messageSources.processRestartCount = restartCount
}

func (messageSources *MessageSources) SetCheckEnvoyState() {
	select {
	case messageSources.BlockingEnvoyStatusTrigger <- struct{}{}:
		// no-op
	default:
		// no-op
	}
}

func (messageSources *MessageSources) SetPid(pid int) {
	messageSources.forkedPid = pid
}

func (messageSources *MessageSources) SetPidCheckTime(checkTime int64) {
	select {
	case messageSources.lastPidCheckChannel <- checkTime:
		// no-op
	default:
		// no-op
	}
}

func (messageSources *MessageSources) GetTerminateProcess() bool {
	messageSources.readChannels()
	return messageSources.terminateProcess
}

func (messageSources *MessageSources) GetProcessStatus() bool {
	messageSources.readChannels()
	return messageSources.lastProcessStatus
}

func (messageSources *MessageSources) GetProcessRestartCount() int {
	return messageSources.processRestartCount
}

func (messageSources *MessageSources) GetCheckEnvoyStatus() bool {
	messageSources.readChannels()
	return messageSources.checkStatus
}

func (messageSources *MessageSources) GetPid() int {
	return messageSources.forkedPid
}

func (messageSources *MessageSources) GetLastPidCheckTime() int64 {
	messageSources.readChannels()
	return messageSources.lastPidCheck
}

func (messageSources *MessageSources) GetAgentExit() bool {
	messageSources.readChannels()

	// This channel read must block so that the agent runs until
	// a signal is received or the monitored process exits
	<-messageSources.agentExit

	return true
}
