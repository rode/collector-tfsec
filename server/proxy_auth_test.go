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

package server

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var _ = Describe("ProxyAuth", func() {
	var (
		ctx                              context.Context
		expectedRequireTransportSecurity bool
		proxyAuth                        credentials.PerRPCCredentials
		expectedAuthzHeader              string
	)

	BeforeEach(func() {
		expectedRequireTransportSecurity = fake.Bool()
		expectedAuthzHeader = fmt.Sprintf("Bearer %s", fake.LetterN(10))
		meta := metadata.New(map[string]string{
			"authorization": expectedAuthzHeader,
		})

		ctx = metautils.NiceMD(meta).ToIncoming(context.Background())
		proxyAuth = NewProxyAuth(expectedRequireTransportSecurity)
	})

	Describe("GetRequestMetadata", func() {
		var (
			actualMetadata map[string]string
			actualError    error
		)

		JustBeforeEach(func() {
			actualMetadata, actualError = proxyAuth.GetRequestMetadata(ctx)
		})

		It("should not return an error", func() {
			Expect(actualError).NotTo(HaveOccurred())
		})

		It("should proxy the given authorization header", func() {
			Expect(actualMetadata["authorization"]).To(Equal(expectedAuthzHeader))
		})

		When("the authorization header is not set", func() {
			BeforeEach(func() {
				ctx = context.Background()
			})

			It("should return no metadata", func() {
				Expect(actualMetadata).To(BeEmpty())
			})
		})
	})

	Describe("RequireTransportSecurity", func() {
		It("should return the transport security setting", func() {
			Expect(proxyAuth.RequireTransportSecurity()).To(Equal(expectedRequireTransportSecurity))
		})
	})
})
