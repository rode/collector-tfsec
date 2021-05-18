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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-tfsec/mocks"
	"github.com/rode/collector-tfsec/proto/v1alpha1"
	"google.golang.org/grpc/status"
)

var _ = Describe("Server", func() {
	var (
		ctx        = context.Background()
		rodeClient *mocks.FakeRodeClient
		server     *tfsecCollector
	)

	BeforeEach(func() {
		rodeClient = &mocks.FakeRodeClient{}

		server = NewTfsecCollector(logger, rodeClient)
	})

	Describe("CreateEventOccurrence", func() {
		var (
			actualError error
			request     *v1alpha1.CreateScanRequest
		)

		BeforeEach(func() {
			request = &v1alpha1.CreateScanRequest{}
		})

		JustBeforeEach(func() {
			_, actualError = server.CreateScan(ctx, request)
		})
	})
})

func getGRPCStatusFromError(err error) *status.Status {
	s, ok := status.FromError(err)
	Expect(ok).To(BeTrue(), "Expected error to be a gRPC status")

	return s
}
