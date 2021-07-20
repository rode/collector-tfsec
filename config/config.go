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

import (
	"flag"
	"github.com/peterbourgon/ff/v3"
	"github.com/rode/rode/common"
)

type Config struct {
	Port       int
	Debug      bool
	ClientConfig *common.ClientConfig
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	c := &Config{
		ClientConfig: common.SetupRodeClientFlags(flags),
	}

	flags.IntVar(&c.Port, "port", 8083, "the port that the collector's gRPC service should listen on")
	flags.BoolVar(&c.Debug, "debug", false, "when set, debug mode will be enabled")

	if err := ff.Parse(flags, args, ff.WithEnvVarNoPrefix()); err != nil {
		return nil, err
	}

	return c, nil
}
