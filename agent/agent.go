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
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-app-mesh-agent/agent/profiling"
	sdkConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/client"
	"github.com/aws/aws-app-mesh-agent/agent/config"
	bootstrap "github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap"
	"github.com/aws/aws-app-mesh-agent/agent/healthcheck"
	"github.com/aws/aws-app-mesh-agent/agent/listenerdraining"
	"github.com/aws/aws-app-mesh-agent/agent/logging"
	"github.com/aws/aws-app-mesh-agent/agent/messagesources"
	_ "github.com/aws/aws-app-mesh-agent/agent/profiling"
	"github.com/aws/aws-app-mesh-agent/agent/server"
	"github.com/aws/aws-app-mesh-agent/agent/stats"
	cap "kernel.org/pub/linux/libs/security/libcap/cap"

	log "github.com/sirupsen/logrus"
	rate "golang.org/x/time/rate"
)

const (
	gracefulDrainQueryKey = "graceful"
)

// Dynamically construct the command arguments we are executing
func buildCommandArgs(agentConfig config.AgentConfig) []string {
	var args []string = []string{agentConfig.CommandPath}

	if agentConfig.EnvoyConfigPath != "" {
		args = append(args, "-c")
		args = append(args, agentConfig.EnvoyConfigPath)
	}

	if agentConfig.EnvoyLogLevel != "" {
		args = append(args, "-l")
		args = append(args, agentConfig.EnvoyLogLevel)
	}

	if agentConfig.EnvoyConcurrency > 0 {
		args = append(args, "--concurrency")
		args = append(args, strconv.Itoa(agentConfig.EnvoyConcurrency))
	} else if agentConfig.EnableRelayModeForXds {
		args = append(args, "--concurrency")
		args = append(args, config.ENVOY_CONCURRENCY_FOR_RELAY_DEFAULT)
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

// When AppNet agent is run as a non-root user, linux capabilities are not preserved on the Envoy process
// unless those are added to Agent's (parent) Inheritable and Ambient capability set. This requires the corresponding
// flag been set on the Agent binary during build process.
// The NET_ADMIN capability is required for tproxy settings in service connect bridge mode listener.
func setAgentCapabilities() error {
	capSet := cap.GetProc()
	if hasNetAdmin, _ := capSet.GetFlag(cap.Permitted, cap.NET_ADMIN); hasNetAdmin {
		log.Infof("Found NET_ADMIN capability in Agent's Permitted Flag, raising it in Inheritable and Ambient flags for Envoy to inherit.")
		if hasSetPCap, _ := capSet.GetFlag(cap.Permitted, cap.SETPCAP); !hasSetPCap {
			return fmt.Errorf("agent has NET_ADMIN capability but, not SETPCAP in its Permitted Flag. Envoy will not be started with NET_ADMIN capability")
		}
		iabVector := cap.IABGetProc()
		err := iabVector.SetVector(cap.Inh, true, cap.NET_ADMIN)
		if err != nil {
			log.Errorf("Failed to set NET_ADMIN in Agent's Inheritable capability vector: %v", err)
			return err
		}
		err = iabVector.SetVector(cap.Amb, true, cap.NET_ADMIN)
		if err != nil {
			log.Errorf("Failed to set NET_ADMIN in Agent's Ambient capability vector: %v", err)
			return err
		}

		err = iabVector.SetProc()
		if err != nil {
			log.Errorf("Failed to set NET_ADMIN capability in Agent's Inheritable and Ambient set: %v", err)
			return err
		}
	}
	return nil
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

		if agentConfig.ProfilingEnabled {
			// Try uploading the profiling data just in case it was not triggered while
			// signal handling. This will cover cases where no signal termination was
			// received by the Envoy process crashed by itself. If there is already
			// profiling upload to S3 in process it will just return.
			uploadProfilingData(agentConfig, messageSource)
			// If profiling is enabled then wait for some time until profile data is uploaded
			// to S3. ListenerDrainWaitTime is a reasonable time to wait.
			// After the success or failure of upload we would signal `SetAgentExit`.
			log.Infof("Waiting %ds for Agent to upload profiler data to S3.", int(agentConfig.ListenerDrainWaitTime.Seconds()))
			time.Sleep(agentConfig.ListenerDrainWaitTime)
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

	agentPid := os.Getpid()
	isInit := agentPid == 1

	log.Debugf("Agent is running as pid [%d]", agentPid)

	go func() {
		for {
			sig := <-signalChan
			switch sig {
			case syscall.SIGCHLD:
				if isInit {
					for {
						// Reap all forked processes, that have been spawned elsewhere
						// https://www.ianlewis.org/en/almighty-pause-container
						_, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
						if err != nil {
							break
						}
					}
				}

			case syscall.SIGTERM:
				fallthrough
			case syscall.SIGQUIT:
				// Note: If profiling is enabled then Envoy is forcefully quit without graceful draining of listeners.
				// Hence, the profiling enabled Envoy image should not be used in production.
				// Swap below two method calls if you want to gracefully drain first before uploading profiles to S3.
				uploadProfilingData(agentConfig, messageSources)
				gracefullyDrainEnvoyListeners(agentConfig)
				messageSources.SetAgentExit()
			default:
				log.Debugf("Received unhandled signal [%v]\n", sig)
			}
		}
	}()
}

func forceQuitQuitQuitEnvoy(agentConfig config.AgentConfig) {
	envoyQuitQuitQuitUrl := fmt.Sprintf("%s://%s:%d%s",
		agentConfig.EnvoyServerScheme,
		agentConfig.EnvoyServerHostName,
		agentConfig.EnvoyServerAdminPort,
		"/quitquitquit")

	log.Infof("Forcefully quit Envoy...")

	httpClient, err := client.CreateDefaultHttpClientForEnvoyServer(agentConfig)
	if err != nil {
		log.Errorf("unable to create a default Http Client: %v", err)
		return
	}

	res, err := httpClient.Post(envoyQuitQuitQuitUrl, "text/html; charset=utf-8", nil)

	if err != nil {
		log.Warnf("Unable to quit Envoy: %v", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Warnf("Failed to quit Envoy [response %d - %s]", res.StatusCode, res.Status)
		return
	}

	log.Infof("Waiting 1s for Envoy to quit.")
	time.Sleep(1 * time.Second)
}

// TODO: Refactor this to reuse functionality from listenerdraining package
func gracefullyDrainEnvoyListeners(agentConfig config.AgentConfig) {
	envoyListenerDrainUrl := fmt.Sprintf("%s://%s:%d%s?%s",
		agentConfig.EnvoyServerScheme,
		agentConfig.EnvoyServerHostName,
		agentConfig.EnvoyServerAdminPort,
		agentConfig.EnvoyListenerDrainUrl,
		gracefulDrainQueryKey)

	log.Infof("Draining Envoy listeners...")
	req, _ := client.CreateRetryableAgentRequest(http.MethodPost, envoyListenerDrainUrl, nil)
	httpClient, err := client.CreateRetryableHttpClientForEnvoyServer(agentConfig)
	if err != nil {
		log.Error("Unable to create Retryable Http Client: ", err)
		return
	}
	res, err := httpClient.Do(req)
	if err != nil {
		log.Error("Unable to drain Envoy listeners: ", err)
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
		log.Warn("Unable to read drain response from Envoy: ", err)
	}

	responseContent := string(responseData)
	// Logging this for sanity
	log.Debugf("Response from drain listeners URL: %s", responseContent)

	log.Infof("Waiting %ds for Envoy to drain listeners.", int(agentConfig.ListenerDrainWaitTime.Seconds()))
	time.Sleep(agentConfig.ListenerDrainWaitTime)
}

func uploadProfilingData(agentConfig config.AgentConfig, messageSources *messagesources.MessageSources) {
	if agentConfig.ProfilingEnabled {
		if !messageSources.GetProfilingStarted() {
			messageSources.SetProfilingStarted()
			// Force quit Envoy so that we force profile generation. We are not gracefully draining the Envoy listeners
			// because not enough time to do both upload profiler data and drain listeners. So expect some request
			// failure while using profiler enabled Envoy image during task/pod termination or replacement.
			forceQuitQuitQuitEnvoy(agentConfig)

			log.Infof("Profiling is enabled, will upload CPU & Heap profile data to S3...")
			s3BucketRegion, accountID, err := profiling.GetRegionAndAccountID()
			if err != nil {
				log.Errorf("Failed to get region & accountID with error: %v", err)
			} else {
				sdkDefaultConfig, err := sdkConfig.LoadDefaultConfig(context.TODO(), sdkConfig.WithRegion(s3BucketRegion))
				if err != nil {
					log.Errorf("couldn't load default configuration due to: %v", err)
				} else {
					profilingDataUploader := profiling.S3DataUploader{
						ProfilerS3Bucket: agentConfig.ProfilerS3Bucket,
						CpuProfilePath:   agentConfig.CpuProfilePath,
						HeapProfilePath:  agentConfig.HeapProfilePath,
						S3Client:         s3.NewFromConfig(sdkDefaultConfig),
						AccountID:        accountID,
						S3BucketRegion:   s3BucketRegion,
					}
					if err := profilingDataUploader.UploadProfileToS3Bucket(); err != nil {
						log.Errorf("Failed to upload envoy heap/cpu profile data to S3 bucket for reason: %v\\n", err)
					}
				}
			}
		} else {
			log.Debugf("Profile collection started already")
		}
	} else {
		log.Debugf("No profiling enabled.")
	}
}

func setupHttpServer(agentConfig config.AgentConfig,
	healthStatus *healthcheck.HealthStatus,
	snapshotter *stats.Snapshotter,
	messageSources *messagesources.MessageSources) {

	if agentConfig.AgentAdminMode == config.UDS {
		// When starting a UDS HttpServer, UDS path needs to be removed first if it exists,
		// or there will be 'address already in use' error
		if err := os.Remove(agentConfig.AgentAdminUdsPath); err != nil && !os.IsNotExist(err) {
			log.Fatalf("Failed to remove Agent Admin UDS path:[%s], %v", agentConfig.AgentAdminUdsPath, err)
			messageSources.SetAgentExit()
			return
		}
	}

	limiter := rate.NewLimiter(config.TPS_LIMIT, config.BURST_TPS_LIMIT)

	envoyLoggingHandler := logging.EnvoyLoggingHandler{
		AgentConfig: agentConfig,
		Limiter:     limiter,
	}

	envoyPrometheusStatsHandler := stats.EnvoyPrometheusStatsHandler{
		AgentConfig: agentConfig,
		Limiter:     limiter,
		Snapshotter: snapshotter,
	}

	healthHandler := healthcheck.HealthStatusHandler{
		HealthStatus: healthStatus,
		Limiter:      limiter,
	}

	envoyListenerDrainHandler := listenerdraining.EnvoyListenerDrainHandler{
		AgentConfig: agentConfig,
		Limiter:     limiter,
	}

	httpHandlers := server.HandlerSpec{
		config.AGENT_STATUS_ENDPOINT_URL:         healthHandler.EnvoyStatus,
		config.AGENT_LOGGING_ENDPOINT_URL:        envoyLoggingHandler.LoggingHandler,
		config.AGENT_STATS_ENDPOINT_URL:          envoyPrometheusStatsHandler.HandleStats,
		config.AGENT_LISTENER_DRAIN_ENDPOINT_URL: envoyListenerDrainHandler.HandleDraining,
	}

	go server.StartHttpServer(agentConfig, httpHandlers, messageSources)
}

func setupUdsForEnvoyAdmin(agentConfig config.AgentConfig, messageSources *messagesources.MessageSources) {
	if agentConfig.EnvoyAdminMode == config.UDS {
		// create the envoy admin uds file to avoid failure of starting health check
		// in uds mode, health check http client is connecting to envoy admin uds
		if fileInfo, err := os.Stat(agentConfig.EnvoyServerAdminUdsPath); !os.IsNotExist(err) {
			log.Debugf("Envoy Admin UDS [%s] already created", agentConfig.EnvoyServerAdminUdsPath)
			if fileInfo.Mode().Perm() != os.FileMode(config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT) {
				if err := os.Chmod(agentConfig.EnvoyServerAdminUdsPath, config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT); err != nil {
					log.Errorf("Failed to change Envoy Admin UDS [%s] file permission to [%d]: %v. Exiting Agent",
						agentConfig.EnvoyServerAdminUdsPath, config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT, err)
					messageSources.SetAgentExit()
				}
			}
			return
		}
		unixAddr := net.UnixAddr{Name: agentConfig.EnvoyServerAdminUdsPath}
		listener, err := net.ListenUnix(config.NETWORK_SOCKET_UNIX, &unixAddr)
		if err != nil {
			log.Errorf("Failed to create Envoy Admin UDS [%s]: %v. Exiting Agent",
				agentConfig.EnvoyServerAdminUdsPath, err)
			messageSources.SetAgentExit()
		}
		// keep uds file, when envoy starts it will re-link/re-use this uds
		listener.SetUnlinkOnClose(false)
		listener.Close()
		if err := os.Chmod(agentConfig.EnvoyServerAdminUdsPath, config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT); err != nil {
			log.Errorf("Failed to change Envoy Admin UDS [%s] file permission to [%d]: %v. Exiting Agent",
				agentConfig.EnvoyServerAdminUdsPath, config.ENVOY_ADMIN_UDS_FILE_MODE_DEFAULT, err)
			messageSources.SetAgentExit()
		}
	}
}

func pollEnvoyReadiness(conf config.AgentConfig) error {
	tick := time.NewTicker(time.Duration(conf.AgentPollEnvoyReadinessInterval) * time.Second)
	defer tick.Stop()

	var after <-chan time.Time
	if conf.AgentPollEnvoyReadinessTimeout > 0 {
		timer := time.NewTimer(time.Duration(conf.AgentPollEnvoyReadinessTimeout) * time.Second)
		after = timer.C
		defer timer.Stop()
	}

	// one-off request path
	if conf.AgentPollEnvoyReadinessInterval == 0 || conf.AgentPollEnvoyReadinessTimeout == 0 {
		httpClient, err := client.CreateHttpClientForAgentServer(conf)
		if err != nil {
			log.Errorf("Failed to create AppNet Agent HTTP client %v", err)
			return err
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1%s", config.AGENT_STATUS_ENDPOINT_URL), nil)
		if err != nil {
			log.Errorf("Failed to create request: (%v) %v", req, err)
			return err
		}

		res, err := httpClient.Do(req)

		if err != nil {
			log.Errorf("Request failed %v", err)
			return err
		}

		body, err := ioutil.ReadAll(res.Body)
		defer res.Body.Close()

		status := healthcheck.HealthStatus{}

		err = json.Unmarshal(body, &status)
		if err != nil {
			log.Errorf("Failed to unmarshal response: [%s] %v", string(body), err)
			return err
		}

		log.Debugf("Envoy is %s", status.HealthStatus)
		if status.HealthStatus != healthcheck.Healthy {
			return fmt.Errorf("Envoy is not healthy: %v", status.HealthStatus)
		}

		return nil
	}

	// polling request path
	log.Debugf("Polling at interval of %ds with timeout of %ds", conf.AgentPollEnvoyReadinessInterval, conf.AgentPollEnvoyReadinessTimeout)
	for {
		select {
		case <-tick.C:
			httpClient, err := client.CreateHttpClientForAgentServer(conf)
			if err != nil {
				log.Errorf("Failed to create IPC HTTP client %v", err)
				continue
			}

			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1%s", config.AGENT_STATUS_ENDPOINT_URL), nil)
			if err != nil {
				log.Errorf("Failed to create request: (%v) %v", req, err)
				continue
			}

			res, err := httpClient.Do(req)
			if err != nil {
				log.Errorf("Request failed %v", err)
				continue
			}

			body, err := ioutil.ReadAll(res.Body)
			defer res.Body.Close()

			status := healthcheck.HealthStatus{}

			err = json.Unmarshal(body, &status)
			if err != nil {
				log.Errorf("Failed to unmarshal response: [%s] %v", string(body), err)
				continue
			}

			log.Debugf("Envoy is %s", status.HealthStatus)
			if status.HealthStatus == healthcheck.Healthy {
				return nil
			}

			// if unhealthy continue ticking
		case <-after:
			log.Debugf("Timed out after %v", conf.AgentPollEnvoyReadinessTimeout)
			return fmt.Errorf("Timed out after %v", conf.AgentPollEnvoyReadinessTimeout)
		}
	}
}

func main() {

	// Update capabilities of Agent process before starting Envoy
	er := setAgentCapabilities()
	if er != nil {
		// Failed to set Agent's capabilities but continuing bootstrap as capabilities may not be needed by Envoy's dynamic config
		log.Errorf("Error while modifying Agent's capabilities: %v", er)
	}

	var agentStartTime = time.Now()
	var messageSources messagesources.MessageSources
	var agentConfig config.AgentConfig
	var healthStatus healthcheck.HealthStatus
	var snapshotter stats.Snapshotter

	agentConfig.ParseFlags(os.Args)
	agentConfig.SetDefaults()

	// TODO: Move this logic to envoy_bootstrap.go so we can write unit test for it.
	if agentConfig.EnableRelayModeForXds {
		err := bootstrap.CreateRelayBootstrapYamlFile(agentConfig)
		if err != nil {
			log.Errorf("Failed to create relay bootstrap configuration yaml file:[%s] %v", agentConfig.EnvoyConfigPath, err)
			os.Exit(1)
		}
	} else {
		err := bootstrap.CreateBootstrapYamlFile(agentConfig)
		if err != nil {
			log.Errorf("Failed to create bootstrap configuration yaml file:[%s] %v", agentConfig.EnvoyConfigPath, err)
			os.Exit(1)
		}
	}

	// Setup channels for various agent operations
	messageSources.SetupChannels()

	logging.SetupLogger(&agentConfig)

	if agentConfig.AgentPollEnvoyReadiness {
		if err := pollEnvoyReadiness(agentConfig); err != nil {
			log.Errorf("Polling envoy readiness failed with error: %v\n", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	setupSignalHandling(agentConfig, &messageSources)
	setupUdsForEnvoyAdmin(agentConfig, &messageSources)

	// Start the configured binary and keep it alive
	go keepCommandAlive(agentConfig, &messageSources)
	defer stopProcesses(agentConfig.StopProcessWaitTime, &messageSources)

	go healthStatus.StartHealthCheck(agentStartTime, agentConfig, &messageSources)
	if agentConfig.EnableStatsSnapshot {
		log.Debug("Enabling stats snapshot...")
		go snapshotter.StartSnapshot(agentConfig)
	}

	// Enable CPU & Heap profiling
	if agentConfig.ProfilingEnabled {
		// TODO: Store the files on a sub-folder with names uniquely generated (based on Pid?) to avoid over writing on restart.
		log.Debugf("Enabling CPU profiling at path: %s and Heap profiling at path: %s...",
			agentConfig.CpuProfilePath,
			agentConfig.HeapProfilePath)
		os.Setenv("CPUPROFILE", agentConfig.CpuProfilePath)
		os.Setenv("HEAPPROFILE", agentConfig.HeapProfilePath)
	}

	// Start the agent http server only if APPNET_AGENT_ADMIN_MODE is set
	if _, exists := os.LookupEnv("APPNET_AGENT_ADMIN_MODE"); exists {
		// TODO: Refactor this - we can have an http server struct that contains the healthStatus and Snapshotter
		// and other resources for the server. Otherwise, this arg list is going to always increase when we add more
		// handlers that needs extra process running alongside the server.
		setupHttpServer(agentConfig, &healthStatus, &snapshotter, &messageSources)
	}

	// Block until we are told its ok to exit
	messageSources.GetAgentExit()
	os.Exit(0)
}
