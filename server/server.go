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
	"strings"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/rode/collector-tfsec/proto/v1alpha1"
	pb "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	collectorNoteName = "projects/rode/notes/tfsec"
)

type tfsecCollector struct {
	logger *zap.Logger
	rode   pb.RodeClient
}

func NewTfsecCollector(logger *zap.Logger, rode pb.RodeClient) *tfsecCollector {
	return &tfsecCollector{
		logger,
		rode,
	}
}

func (tf *tfsecCollector) CreateScan(ctx context.Context, request *v1alpha1.CreateScanRequest) (*empty.Empty, error) {
	scanStart := createDiscoveryOccurrence(request, discovery_go_proto.Discovered_SCANNING)
	scanEnd := createDiscoveryOccurrence(request, discovery_go_proto.Discovered_FINISHED_SUCCESS)
	scanEnd.CreateTime = scanStart.CreateTime
	occurrences := []*grafeas_go_proto.Occurrence{
		scanStart,
		scanEnd,
	}

	for _, result := range request.Results {
		occurrences = append(occurrences, mapScanResultToVulnOccurrence(request, result, scanEnd.CreateTime))
	}

	_, err := tf.rode.BatchCreateOccurrences(ctx, &pb.BatchCreateOccurrencesRequest{
		Occurrences: occurrences,
	})

	if err != nil {
		return nil, err
	}

	return &empty.Empty{}, nil
}

func createDiscoveryOccurrence(request *v1alpha1.CreateScanRequest, status discovery_go_proto.Discovered_AnalysisStatus) *grafeas_go_proto.Occurrence {
	return &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: request.CommitUri,
		},
		NoteName:   collectorNoteName,
		Kind:       common_go_proto.NoteKind_DISCOVERY,
		CreateTime: timestamppb.Now(),
		Details: &grafeas_go_proto.Occurrence_Discovered{
			Discovered: &discovery_go_proto.Details{
				Discovered: &discovery_go_proto.Discovered{
					ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
					AnalysisStatus:     status,
				}},
		},
	}
}

func mapScanResultToVulnOccurrence(request *v1alpha1.CreateScanRequest, violation *v1alpha1.TfsecScanRuleViolation, timestamp *timestamp.Timestamp) *grafeas_go_proto.Occurrence {
	return &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: request.CommitUri,
		},
		CreateTime: timestamp,
		NoteName:   collectorNoteName,
		Kind:       common_go_proto.NoteKind_VULNERABILITY,
		Details: &grafeas_go_proto.Occurrence_Vulnerability{
			Vulnerability: &vulnerability_go_proto.Details{
				Type:              "git", // TODO: should this be "terraform"?
				Severity:          mapSeverity(violation.Severity),
				EffectiveSeverity: mapSeverity(violation.Severity),
				ShortDescription:  violation.Description,
				PackageIssue:      mapPackageIssue(request, violation),
			},
		},
	}
}

// map tfsec severity levels to grafeas levels
// tfsec source: https://github.com/tfsec/tfsec/blob/3cb7ae63dd2370439dccad77fc048d17a6225cbc/internal/app/tfsec/scanner/result.go#L25-L29
// It appears that none of the default rules use the info severity
func mapSeverity(severity string) vulnerability_go_proto.Severity {
	switch severity {
	case "ERROR":
		return vulnerability_go_proto.Severity_HIGH
	case "WARNING":
		return vulnerability_go_proto.Severity_MEDIUM
	case "INFO":
		return vulnerability_go_proto.Severity_MINIMAL
	default:
		return vulnerability_go_proto.Severity_SEVERITY_UNSPECIFIED
	}
}

func mapPackageIssue(request *v1alpha1.CreateScanRequest, violation *v1alpha1.TfsecScanRuleViolation) []*vulnerability_go_proto.PackageIssue {
	location := strings.TrimPrefix(violation.Location.Filename, request.PathPrefix+"/")

	return []*vulnerability_go_proto.PackageIssue{
		{
			AffectedLocation: &vulnerability_go_proto.VulnerabilityLocation{
				CpeUri:  fmt.Sprintf("https://tfsec.dev/docs/%s/%s/", violation.RuleProvider, violation.RuleId),
				Package: location,
				Version: &package_go_proto.Version{
					Name: location,
					Kind: package_go_proto.Version_NORMAL,
				},
			},
		},
	}
}
