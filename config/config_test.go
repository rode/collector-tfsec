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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"

	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Describe("Build", func() {
		DescribeTable("invalid configuration", func(flags []string) {
			c, err := Build("collector", flags)

			Expect(err).To(HaveOccurred())
			Expect(c).To(BeNil())
		},
			Entry("bad port", []string{"--port=foo"}),
			Entry("bad debug", []string{"--debug=baz"}),
		)

		DescribeTable("successful configuration", func(flags []string, expected interface{}) {
			c, err := Build("collector", flags)

			Expect(err).To(BeNil())
			Expect(c).To(Equal(expected))
		},
			Entry("default config", []string{}, &Config{
				Port:  8083,
				Debug: false,
				RodeConfig: &RodeConfig{
					Host: "rode:50051",
				},
			}),
			Entry("Rode host flag", []string{"--rode-host=bar"}, &Config{
				Port:  8083,
				Debug: false,
				RodeConfig: &RodeConfig{
					Host: "bar",
				},
			}),
			Entry("Rode insecure flag", []string{"--rode-insecure=true"}, &Config{
				Port:  8083,
				Debug: false,
				RodeConfig: &RodeConfig{
					Host:     "rode:50051",
					Insecure: true,
				},
			}),
		)
	})
})
