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

	"github.com/golang/protobuf/ptypes"
	"github.com/rode/new-collector-template/proto/v1alpha1"
	pb "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/build_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/provenance_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/source_go_proto"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	rodeProjectId            = "projects/rode"
	newCollectorTemplateNote = rodeProjectId + "/notes/new_collector_template"
)

type NewCollectorTemplateServer struct {
	logger *zap.Logger
	rode   pb.RodeClient
}

func NewNewCollectorTemplateServer(logger *zap.Logger, rode pb.RodeClient) *NewCollectorTemplateServer {
	return &NewCollectorTemplateServer{
		logger,
		rode,
	}
}

func (s *NewCollectorTemplateServer) CreateEventOccurrence(ctx context.Context, request *v1alpha1.CreateEventOccurrenceRequest) (*v1alpha1.CreateEventOccurrenceResponse, error) {
	log := s.logger.Named("CreateEventOccurrence")

	log.Debug("received request", zap.Any("request", request))

	o := &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: "github.com/rode/rode@bca0e1b89be42a61131b6de09fd2836e7b00c252",
		},
		NoteName: newCollectorTemplateNote,
		Kind:     common_go_proto.NoteKind_BUILD,
		Details: &grafeas_go_proto.Occurrence_Build{
			Build: &build_go_proto.Details{
				Provenance: &provenance_go_proto.BuildProvenance{
					Id:         request.Name,
					ProjectId:  rodeProjectId,
					CreateTime: ptypes.TimestampNow(),
					SourceProvenance: &provenance_go_proto.Source{
						Context: &source_go_proto.SourceContext{
							Context: &source_go_proto.SourceContext_Git{
								Git: &source_go_proto.GitSourceContext{
									Url:        "github.com/rode/rode",
									RevisionId: "bca0e1b89be42a61131b6de09fd2836e7b00c252",
								}},
						},
					},
				},
			},
		},
	}

	batchRequest := &pb.BatchCreateOccurrencesRequest{
		Occurrences: []*grafeas_go_proto.Occurrence{o},
	}

	response, err := s.rode.BatchCreateOccurrences(ctx, batchRequest)
	if err != nil {
		log.Error("Error creating occurrence", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "Error creating occurrence: %s", err)
	}

	log.Info("Occurrence created")
	return &v1alpha1.CreateEventOccurrenceResponse{
		Id: response.Occurrences[0].Name,
	}, nil
}
