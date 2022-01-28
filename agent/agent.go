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

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"
	"github.com/aws/aws-app-mesh-agent/agent/healthcheck"
	"github.com/aws/aws-app-mesh-agent/agent/logging"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"

	log "github.com/sirupsen/logrus"
)

// Dynamically construct the command arguments we are executing
func buildCommandArgs(agentConfig config.AgentConfig) []string {
	var args []string = []string{agentConfig.CommandPath}

	if agentConfig.EnvoyConfigPath != nil && len(*agentConfig.EnvoyConfigPath) > 0 {
		args = append(args, "-c")
		args = append(args, *agentConfig.EnvoyConfigPath)
	}

	if agentConfig.EnvoyLogLevel != nil && len(*agentConfig.EnvoyLogLevel) > 0 {
		args = append(args, "-l")
		args = append(args, *agentConfig.EnvoyLogLevel)
	}

	listenerDrainWaitTime := int(agentConfig.ListenerDrainWaitTime / time.Second)
	if listenerDrainWaitTime > 0 {
		args = append(args, "--drain-time-s")
		args = append(args, strconv.Itoa(listenerDrainWaitTime))
	}

	if len(agentConfig.CommandArgs) > 0 {
		args = append(args, agentConfig.CommandArgs...)
	}

	return args
}

func monitorCommand(pid int, messageSource *messagesources.MessageSources, pollInterval time.Duration) syscall.WaitStatus {

	// This loop uses non-blocking calls to check the state of the process and
	// continually write to messageSource.processState channel
	var wstatus syscall.WaitStatus
	var rusage syscall.Rusage
	var options int = syscall.WNOHANG
	var pidIsAlive bool = true

	start := time.Now()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for pidIsAlive {
		select {
		case <-ticker.C:
			if messageSource.GetTerminateProcess() {
				log.Infof("Sending sigterm to pid [%d]", pid)
				syscall.Kill(pid, syscall.SIGTERM)
			}

			wpid, err := syscall.Wait4(pid, &wstatus, options, &rusage)
			log.Tracef("[%d] WaitPid returned [%d - %v]", pid, wpid, err)

			if err != nil || wpid == pid {
				log.Warnf("[Envoy process %d] Exited with code [%d]", wpid, wstatus.ExitStatus())
				log.Warnf("[Envoy process %d] Additional Exit data: [Core Dump: %t][Normal Exit: %t][Process Signalled: %t]",
					wpid, wstatus.CoreDump(), wstatus.Exited(), wstatus.Signaled())
				pidIsAlive = false
			}

			messageSource.SetPid(pid)
			messageSource.SetProcessState(pidIsAlive)
			messageSource.SetPidCheckTime(time.Now().Unix()) // This data isn't used yet
		}
	}

	log.Debugf("[%d] Process exited after [%f seconds]...", pid, time.Since(start).Seconds())
	messageSource.SetProcessState(pidIsAlive)
	messageSource.SetCheckEnvoyState()

	return wstatus
}

func startCommand(agentConfig config.AgentConfig, cmdArgs []string) (int, error) {

	var workingDirectory string
	var environmentVars []string = os.Environ()

	if len(agentConfig.OutputFileDescriptors) == 0 {
		// If the file descriptors are not set in the agentConfig we will abort.
		// We need stdin/stdout/stderr from the agentIoWriter so that redirected output
		// gets to the intended destination
		log.Fatal("No file descriptors are set for forked command output")
	}

	attr := syscall.ProcAttr{
		Dir:   workingDirectory,
		Env:   environmentVars,
		Files: agentConfig.OutputFileDescriptors,
		Sys:   nil,
	}

	log.Infof("Executing command: %s", cmdArgs)

	pid, err := syscall.ForkExec(cmdArgs[0], cmdArgs, &attr)
	if err != nil {
		log.Errorf("Unable to start process: %v", err)
	}

	return pid, err
}

// start the command object, restarting up to the configured limit
func keepCommandAlive(agentConfig config.AgentConfig, messageSource *messagesources.MessageSources) {
	var restartCount int = 0

	// If we are exiting this function, then we should exit the agent.  ECS
	// scheduler must replace the task.
	defer messageSource.SetAgentExit()

	for {

		messageSource.SetProcessRestartCount(restartCount)

		// Build the command line arguments and execute the program
		cmdArgs := buildCommandArgs(agentConfig)

		pid, err := startCommand(agentConfig, cmdArgs)
		if err != nil {
			log.Errorf("Unable to fork process: %v\n", err)
		}

		log.Debugf("Started process [%d]\n", pid)
		waitStatus := monitorCommand(pid, messageSource, agentConfig.PidPollInterval)
		log.Debugf("monitorCommand returned [%d]\n", waitStatus.ExitStatus())

		// Don't restart if we were signalled
		if waitStatus.Signaled() {
			log.Debugf("Terminate is set. Sending [%d] a SIGTERM", pid)
			break
		}

		if restartCount >= agentConfig.EnvoyRestartCount {
			break
		}
		restartCount++
	}
}

func stopProcesses(maxWaitTime time.Duration, messageSources *messagesources.MessageSources) {
	messageSources.SetTerminateProcess(true)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		var processActive bool
		var startTime = time.Now()
		// Check process state every second
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		defer wg.Done()

		for processActive {
			select {
			case <-ticker.C:
				processActive = messageSources.GetProcessStatus()
				if !processActive {
					return
				}

				if time.Since(startTime) > maxWaitTime {
					processActive = false
				}
			}
		}

		pid := messageSources.GetPid()
		if pid > 0 {
			log.Infof("Killing pid [%d]", pid)
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}()

	wg.Wait()
}

func setupSignalHandling(agentConfig config.AgentConfig, messageSources *messagesources.MessageSources) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	go func() {
		for {
			sig := <-signalChan
			switch sig {

			case syscall.SIGTERM:
				fallthrough
			case syscall.SIGQUIT:
				drainEnvoyListeners(agentConfig)
				messageSources.SetAgentExit()
			default:
				log.Debugf("Received unhandled signal [%v]\n", sig)
			}
		}
	}()
}

func drainEnvoyListeners(agentConfig config.AgentConfig) {
	envoyListenerDrainUrl := fmt.Sprintf("http://127.0.0.1:%d%s",
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyListenerDrainUrl)

	log.Infof("Draining Envoy listeners...")
	req, _ := http.NewRequest("POST", envoyListenerDrainUrl, nil)
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", config.APPNET_USER_AGENT)

	var httpClient = &http.Client{Timeout: 250 * time.Millisecond}
	res, err := httpClient.Do(req)
	if err != nil {
		log.Error("Unable to drain Envoy listeners: %w", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Errorf("Failed to drain Envoy listeners [response %d - %s]", res.StatusCode, res.Status)
		return
	}

	responseData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		// We received HTTP 200, so will wait for Envoy to drain
		log.Warn("Unable to read drain response from Envoy: %w", err)
	}

	responseContent := string(responseData)
	// Logging this for sanity
	log.Debugf("Response from drain listeners URL: %s", responseContent)

	log.Infof("Waiting %ds for Envoy to drain listeners.", int(agentConfig.ListenerDrainWaitTime.Seconds()))
	time.Sleep(agentConfig.ListenerDrainWaitTime)
}

func main() {

	var agentStartTime = time.Now()
	var messageSources messagesources.MessageSources
	var agentConfig config.AgentConfig
	var healthStatus healthcheck.HealthStatus

	agentConfig.SetDefaults()

	// Setup channels for various agent operations
	messageSources.SetupChannels()

	logging.SetupLogger(&agentConfig)

	setupSignalHandling(agentConfig, &messageSources)

	// Start the configured binary and keep it alive
	go keepCommandAlive(agentConfig, &messageSources)
	defer stopProcesses(agentConfig.StopProcessWaitTime, &messageSources)

	go healthStatus.StartHealthCheck(agentStartTime, agentConfig, &messageSources)

	// Block until we are told its ok to exit
	messageSources.GetAgentExit()
	os.Exit(0)
}
