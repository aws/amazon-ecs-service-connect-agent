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

package profiling

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-app-mesh-agent/agent/envoy_bootstrap/platforminfo"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type S3DataUploader struct {
	ProfilerS3Bucket string
	CpuProfilePath   string
	HeapProfilePath  string
	S3Client         *s3.Client
	AccountID        string
	S3BucketRegion   string
}

func GetRegionAndAccountID() (string, string, error) {
	ecsMapping := make(map[string]interface{})
	if platforminfo.BuildMetadataForEcsPlatform(ecsMapping) {
		ecsPlatformInfo, ok := ecsMapping[platforminfo.EcsPlatformInfoKey].(map[string]interface{})
		if !ok {
			return "", "", fmt.Errorf("failed to get ECS platform info for task arn")
		}
		taskArn, ok := ecsPlatformInfo[platforminfo.EcsTaskArnKey].(string)
		if !ok {
			return "", "", fmt.Errorf("failed to get task arn from ECS platform info")
		}
		// Just get the AWS Account ID & Region from taskArn
		taskArnParts := strings.Split(taskArn, ":")
		return taskArnParts[3], taskArnParts[4], nil
	}

	// Trying to get the Account ID from IMDS if getting from Task Metadata was unsuccessful
	var documentMap map[string]interface{}
	document, err := platforminfo.GetEc2InstanceMetadata(platforminfo.DocumentQuery)
	if err != nil {
		return "", "", err
	}

	if err = json.Unmarshal([]byte(document), &documentMap); err != nil {
		return "", "", fmt.Errorf("unable to parse document: %s from IMDS, %v", document, err)
	} else if _, ok := documentMap["accountId"].(string); !ok {
		return "", "", fmt.Errorf("unable to parse document: %s from IMDS to get accountID", document)
	} else if _, ok := documentMap["region"].(string); !ok {
		return "", "", fmt.Errorf("unable to parse document: %s from IMDS to get region", document)
	}
	return documentMap["region"].(string), documentMap["accountId"].(string), nil
}

// GetTaskOrPodID tries to get the task ID from ECS or PodID from K8s.
func (du *S3DataUploader) GetTaskOrPodID() (string, error) {
	ecsMapping := make(map[string]interface{})
	k8sMapping := make(map[string]interface{})
	if platforminfo.BuildMetadataForEcsPlatform(ecsMapping) {
		ecsPlatformInfo, ok := ecsMapping[platforminfo.EcsPlatformInfoKey].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("failed to get ECS platform info for task arn")
		}
		taskArn, ok := ecsPlatformInfo[platforminfo.EcsTaskArnKey].(string)
		if !ok {
			return "", fmt.Errorf("failed to get task arn from ECS platform info")
		}
		// Example taskArn = "arn:aws:ecs:us-west-2:<account_id>:task/<service_name>/<task_id>"
		taskArnSplit := strings.Split(taskArn, "/")
		return fmt.Sprintf("%s-%s", taskArnSplit[1], taskArnSplit[2]), nil
	} else if platforminfo.BuildMetadataForK8sPlatform(k8sMapping) {
		k8sPlatformInfo, ok := k8sMapping[platforminfo.K8sPlatformInfoKey].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("failed to get k8s platform info for pod Uid")
		}
		podUid, ok := k8sPlatformInfo[platforminfo.PodUidKey].(string)
		if !ok {
			return "", fmt.Errorf("failed to get podUid from k8s platform info")
		}
		return podUid, nil
	}
	return "", nil
}

// CompressFolder compresses a folder at sourcePath and writes the resulting tar.gz file to destinationPath
func (du *S3DataUploader) CompressFolder(sourcePath, destinationPath string) error {
	// Create destination file
	log.Infof("SourcePath: %v, DestinationPath: %v", sourcePath, destinationPath)
	destination, err := os.Create(destinationPath)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer destination.Close()

	// Gzip writer
	gzipWriter := gzip.NewWriter(destination)
	defer gzipWriter.Close()

	// Tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Walk the directory
	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create header
		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return fmt.Errorf("error creating header: %v", err)
		}

		log.Infof("path: %v, sourcePath: %v, len(sourcePath): %v", path, sourcePath, len(sourcePath))
		// Update header to correct path
		header.Name = path
		log.Infof("header.Name: %v", header.Name)
		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("error writing header: %v", err)
		}

		// If it's a regular file, write it to the tar writer
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("error opening file: %v", err)
			}
			defer file.Close()

			_, err = io.Copy(tarWriter, file)
			if err != nil {
				return fmt.Errorf("error copying file to tar writer: %v", err)
			}
		}

		return nil
	})
}

// UploadObject uploads an object to the S3 bucket
func (du *S3DataUploader) UploadObject(fileName string) error {
	if file, err := os.Open(fileName); err != nil {
		return fmt.Errorf("couldn't open file %v to upload. Here's why: %v\\n", fileName, err)
	} else {
		objectKey := fileName[strings.LastIndex(fileName, "/")+1:]
		defer file.Close()
		_, err := du.S3Client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(du.ProfilerS3Bucket),
			Key:    aws.String(objectKey),
			Body:   file,
		})
		if err != nil {
			return fmt.Errorf("couldn't upload file %v to %v:%v. Here's why: %v\\n",
				fileName, du.ProfilerS3Bucket, objectKey, err)
		}
		log.Infof("Succesfully uploaded file %v to %v:%v.\n", fileName, du.ProfilerS3Bucket, objectKey)
		return nil
	}
}

func (du *S3DataUploader) UploadProfileToS3Bucket() error {
	var err error
	var identifier string
	if du.ProfilerS3Bucket == "" {
		// If ProfilerS3Bucket is not set then construct a default value of format `envoyprofiles-<region>-<AccountID>`.
		du.ProfilerS3Bucket = fmt.Sprintf("envoyprofiles-%s-%s", du.S3BucketRegion, du.AccountID)
		log.Infof("ProfilerS3Bucket was not provided so contructed the default value: %v", du.ProfilerS3Bucket)
	}

	if identifier, err = du.GetTaskOrPodID(); err != nil {
		log.Warnf("unable to get task/pod identified to upload to s3 with specific name because of: %v\n", err)
		identifier = uuid.New().String()
		log.Infof("Will upload profile data as object %s to s3 bucket %s", identifier, du.ProfilerS3Bucket)
	} else {
		log.Infof("Will upload profile data as object %s to s3 bucket %s", identifier, du.ProfilerS3Bucket)
	}

	cpuProfileFolder := du.CpuProfilePath[:strings.LastIndex(du.CpuProfilePath, "/")]
	cpuProfileParentFolder := cpuProfileFolder[:strings.LastIndex(cpuProfileFolder, "/")]
	heapProfileFolder := du.HeapProfilePath[:strings.LastIndex(du.HeapProfilePath, "/")]
	heapProfileParentFolder := heapProfileFolder[:strings.LastIndex(heapProfileFolder, "/")]
	if cpuProfileFolder == heapProfileFolder {
		// Both the folders are the same, so upload a single object
		compressedProfileFile := fmt.Sprintf("%s/%s_profile.tar.gz", cpuProfileParentFolder, identifier)
		if err := du.CompressFolder(cpuProfileFolder, compressedProfileFile); err != nil {
			return err
		}
		if err := du.UploadObject(compressedProfileFile); err != nil {
			return err
		}
	} else {
		// Both the folders are different, so upload each individual folder.
		compressedHeapProfileFile := fmt.Sprintf("%s/%s_heap_profile.tar.gz", heapProfileParentFolder, identifier)
		if err := du.CompressFolder(heapProfileFolder, compressedHeapProfileFile); err != nil {
			return err
		}
		if err := du.UploadObject(compressedHeapProfileFile); err != nil {
			return err
		}
		compressedCpuProfileFile := fmt.Sprintf("%s/%s_cpu_profile.tar.gz", cpuProfileParentFolder, identifier)
		if err := du.CompressFolder(cpuProfileFolder, compressedCpuProfileFile); err != nil {
			return err
		}
		if err := du.UploadObject(compressedCpuProfileFile); err != nil {
			return err
		}
	}
	return nil
}
