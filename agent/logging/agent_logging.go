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
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-app-mesh-agent/agent/config"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

type AgentLogWriter interface {
	io.Writer
	GetOutputFileDescriptors() []uintptr
}

type AgentLogWriterImpl struct {
	fileHandles []*os.File
	defaultSink *os.File
	lock        sync.Mutex
}

func (a *AgentLogWriterImpl) GetOutputFileDescriptors() []uintptr {
	fds := []uintptr{
		a.fileHandles[syscall.Stdin].Fd(),
		a.fileHandles[syscall.Stdout].Fd(),
		a.fileHandles[syscall.Stderr].Fd(),
	}

	log.Tracef("Returning file descriptors: %v", fds)

	return fds
}

func (a *AgentLogWriterImpl) Write(p []byte) (int, error) {
	var bytesWritten int = -1
	var err error = nil

	a.lock.Lock()
	defer a.lock.Unlock()

	if a.defaultSink != nil {
		bytesWritten, err = a.defaultSink.Write(p)
	}
	return bytesWritten, err
}

func copyLogFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return -1, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return -1, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return -1, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return -1, err
	}

	defer destination.Close()
	return io.Copy(destination, source)
}

func CleanupLogFiles(logFile string, maxFilesToKeep int) {
	// if fileCount is zero clean up all the log files matching the logFile
	// pattern
	var logfilePattern string = fmt.Sprintf("%s.*", logFile)
	matches, err := filepath.Glob(logfilePattern)
	if err != nil {
		log.Warnf("Errors when attempting to match glob pattern: %s: [error %v]", logfilePattern, err)
		return
	}

	if len(matches) < maxFilesToKeep {
		return
	}

	// Sort the files in reverse chronological order (newest first)
	sort.Slice(matches, func(i, j int) bool {
		a_parts := strings.Split(matches[i], ".")
		b_parts := strings.Split(matches[j], ".")

		// If the filename does not end in an epoch bubble it to the end
		a_time, err := strconv.ParseInt(a_parts[len(a_parts)-1], 10, 64)
		if err != nil {
			return false
		}

		b_time, err := strconv.ParseInt(b_parts[len(b_parts)-1], 10, 64)
		if err != nil {
			return false
		}
		return a_time > b_time
	})

	for i, f := range matches {
		if i < maxFilesToKeep {
			continue
		}
		os.Remove(f)
	}
}

func (a *AgentLogWriterImpl) monitorAndRotateLog(agentConfig config.AgentConfig, watcher *fsnotify.Watcher) {

	logPath := path.Join(
		agentConfig.EnvoyLoggingDestination,
		agentConfig.EnvoyLogFileName,
	)

	watcher.Add(logPath)

	// We cannot log in this function.  This loop operates on inotify events
	// so logging here ends up begin recursive.
	var maxSize int64 = int64(agentConfig.MaxLogFileSizeMB * 1_048_576)
	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				fileInfo, err := os.Stat(logPath)
				if err != nil {
					continue
				}

				if fileInfo.Size() > maxSize {
					// Append the epoch to the filename.  This represents the end of the log's
					// contents
					var dstFileName string = fmt.Sprintf("%s.%d", logPath, time.Now().Unix())
					copyLogFile(logPath, dstFileName)

					// Truncate the existing log file
					a.defaultSink.Truncate(0)
					a.defaultSink.Seek(0, 0)
					a.defaultSink.Sync()

					// Purge old files, and preserve the configured file count
					CleanupLogFiles(logPath, agentConfig.MaxLogCount)
				}
			}
		}
	}
}

func openDiskLogFile(agentConfig config.AgentConfig) (*os.File, error) {
	logFullPath := path.Join(agentConfig.EnvoyLoggingDestination, agentConfig.EnvoyLogFileName)
	log.Debugf("Writing output to %s\n", logFullPath)

	logFile, err := os.Create(logFullPath)
	if err != nil {
		log.Errorf("Unable to open the full output log path [%s]: %v", logFullPath, err)
		return nil, err
	}

	return logFile, nil
}

func getOutputRedirection(agentconfig config.AgentConfig) ([]*os.File, error) {
	var outputFds []*os.File = make([]*os.File, 3)

	// Set the default file descriptors unless we are configured differently
	outputFds[syscall.Stdin] = os.Stdin
	outputFds[syscall.Stdout] = os.Stdout
	outputFds[syscall.Stderr] = os.Stderr

	// We are configured to log to a disk location
	if agentconfig.EnvoyLoggingDestination != config.ENVOY_LOG_DESTINATION_DEFAULT {

		fileInfo, err := os.Stat(agentconfig.EnvoyLoggingDestination)
		if err != nil {
			log.Errorf("Unable to determine state of log destination %s", agentconfig.EnvoyLoggingDestination)
			return outputFds, err
		}

		if !fileInfo.IsDir() {
			log.Errorf("Log destination %s, is not a directory", agentconfig.EnvoyLoggingDestination)
			return outputFds, errors.New("log destination is not a directory")
		}

		start := time.Now()

		// Create a file and use the copy/truncate method to rotate it.
		redirectedLog, err := openDiskLogFile(agentconfig)
		if err != nil {
			log.Warnf("Unable to redirect output to the configured log file: %v", err)
			return outputFds, err
		}

		// Reset the agent stdout/stderr to the output Fds
		outputFds[syscall.Stdout] = redirectedLog
		outputFds[syscall.Stderr] = redirectedLog

		log.Debugf("Log rotation took [%d us]\n", time.Since(start).Microseconds())
	}

	return outputFds, nil
}

func newAgentLogWriter(agentConfig config.AgentConfig) AgentLogWriter {
	var logger = new(AgentLogWriterImpl)

	fileHandles, err := getOutputRedirection(agentConfig)
	if err != nil {
		log.Warn("Unable to setup log output redirection to file.")
	}

	// If redirection fails we still use the default file descriptors. Logging is still
	// sent to stderr by default
	logger.fileHandles = fileHandles
	logger.defaultSink = logger.fileHandles[syscall.Stderr]

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("Unable to create inotify watcher for log rotation")
		return logger
	}

	go logger.monitorAndRotateLog(agentConfig, watcher)

	return logger
}

// initialize the logger with a specified log format
func SetupLogger(agentConfig *config.AgentConfig) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	})

	if agentConfig != nil {
		agentWriter := newAgentLogWriter(*agentConfig)

		// We need file descriptors for the forked process output.  If we are
		// redirecting to a file, these file descriptors must also point to this
		// same logfile.  Not certain that we can update the file descriptors
		// once they are in use, so this constrains us to a copy/truncate log
		// rotation mechanism
		agentConfig.OutputFileDescriptors = agentWriter.GetOutputFileDescriptors()
		log.SetOutput(agentWriter)
	}

	var logLevel log.Level = log.InfoLevel
	switch agentConfig.EnvoyLogLevel {
	case "debug":
		logLevel = log.DebugLevel
	case "warn":
		logLevel = log.WarnLevel
	case "error":
		logLevel = log.ErrorLevel
	case "trace":
		logLevel = log.TraceLevel
	default:
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
	log.SetFormatter(NewAgentLogFormatter())
}
