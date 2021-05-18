// Copyright 2021 The Rode Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import "flag"

type Config struct {
	Port       int
	Debug      bool
	RodeConfig *RodeConfig
}

type RodeConfig struct {
	Host     string
	Insecure bool
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	c := &Config{
		RodeConfig: &RodeConfig{},
	}

	flags.IntVar(&c.Port, "port", 1233, "the port that the collector's gRPC service should listen on")
	flags.BoolVar(&c.Debug, "debug", false, "when set, debug mode will be enabled")

	flags.StringVar(&c.RodeConfig.Host, "rode-host", "rode:50051", "the host to use to connect to rode")
	flags.BoolVar(&c.RodeConfig.Insecure, "rode-insecure", false, "when set, the connection to rode will not use TLS")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}
