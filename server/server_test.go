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

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/new-collector-template/mocks"
	"github.com/rode/new-collector-template/proto/v1alpha1"
	pb "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = Describe("Server", func() {
	var (
		ctx        context.Context
		mockCtrl   *gomock.Controller
		rodeClient *mocks.MockRodeClient
		server     *NewCollectorTemplateServer
	)

	BeforeEach(func() {
		ctx = context.Background()
		mockCtrl = gomock.NewController(GinkgoT())
		rodeClient = mocks.NewMockRodeClient(mockCtrl)

		server = NewNewCollectorTemplateServer(logger, rodeClient)
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Describe("CreateEventOccurrence", func() {
		var (
			actualError error
			request     *v1alpha1.CreateEventOccurrenceRequest
			response    *v1alpha1.CreateEventOccurrenceResponse
		)

		BeforeEach(func() {
			request = &v1alpha1.CreateEventOccurrenceRequest{
				Name: fake.LetterN(10),
			}
		})

		JustBeforeEach(func() {
			response, actualError = server.CreateEventOccurrence(ctx, request)
		})

		Describe("the occurrence is created successfully", func() {
			var (
				expectedOccurrenceId string
				actualBatchRequest   *pb.BatchCreateOccurrencesRequest
			)

			BeforeEach(func() {
				expectedOccurrenceId = fake.LetterN(10)
				newOccurrence := &grafeas_go_proto.Occurrence{
					Name: expectedOccurrenceId,
				}

				rodeClient.EXPECT().
					BatchCreateOccurrences(ctx, gomock.Any()).
					Do(func(_ context.Context, r *pb.BatchCreateOccurrencesRequest) {
						actualBatchRequest = r
					}).
					Return(&pb.BatchCreateOccurrencesResponse{Occurrences: []*grafeas_go_proto.Occurrence{newOccurrence}}, nil).
					Times(1)
			})

			It("should not return an error", func() {
				Expect(actualError).To(BeNil())
			})

			It("should create a build occurrence", func() {
				actualOccurrence := actualBatchRequest.Occurrences[0]

				Expect(actualOccurrence.Resource.Uri).To(Equal("github.com/rode/rode@bca0e1b89be42a61131b6de09fd2836e7b00c252"))
				Expect(actualOccurrence.NoteName).To(Equal("projects/rode/notes/new_collector_template"))
				Expect(actualOccurrence.Kind).To(Equal(common_go_proto.NoteKind_BUILD))
				Expect(actualOccurrence.GetBuild().Provenance.Id).To(Equal(request.Name))
				Expect(actualOccurrence.GetBuild().Provenance.ProjectId).To(Equal("projects/rode"))
			})

			It("should return the new occurrence id", func() {
				Expect(response.Id).To(Equal(expectedOccurrenceId))
			})
		})

		Describe("an error occurs creating the occurrence", func() {
			var (
				expectedError error
			)

			BeforeEach(func() {
				expectedError = fmt.Errorf(fake.Word())
				rodeClient.EXPECT().
					BatchCreateOccurrences(gomock.Any(), gomock.Any()).
					Return(nil, expectedError).
					Times(1)
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
				Expect(response).To(BeNil())
			})

			It("should set the status to internal server error", func() {
				s := getGRPCStatusFromError(actualError)

				Expect(s.Code()).To(Equal(codes.Internal))
				Expect(s.Message()).To(Equal(fmt.Sprintf("Error creating occurrence: %s", expectedError)))
			})
		})
	})
})

func getGRPCStatusFromError(err error) *status.Status {
	s, ok := status.FromError(err)
	Expect(ok).To(BeTrue(), "Expected error to be a gRPC status")

	return s
}
