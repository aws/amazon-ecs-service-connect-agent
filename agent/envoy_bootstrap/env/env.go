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

package env

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Get(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func Or(key string, orElse string) string {
	if v := Get(key); v != "" {
		return v
	}
	return orElse
}

func OrInt(key string, orElse int) (int, error) {
	v := Get(key)
	if v == "" {
		return orElse, nil
	}
	i, err := strconv.ParseInt(v, 10, strconv.IntSize)
	if err != nil {
		return 0, fmt.Errorf("%s environment variable (\"%s\") must be an integer value.", key, v)
	}
	return int(i), nil
}

func Truthy(key string) (bool, error) {
	return TruthyOrElse(key, false)
}

func TruthyOrElse(key string, orElse bool) (bool, error) {
	v := Or(key, strconv.FormatBool(orElse))
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s environment variable (\"%s\") must be a boolean value.", key, v)
	}
	return b, nil
}
