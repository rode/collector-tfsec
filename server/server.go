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
	"net/url"
	"strings"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/rode/collector-tfsec/proto/v1alpha1"
	pb "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	log := tf.logger.Named("CreateScan")

	log.Info("Received request")
	repoUrl, err := url.ParseRequestURI(request.Repository)
	if err != nil {
		log.Error("Invalid repository uri")
		return nil, status.Errorf(codes.InvalidArgument, "invalid repository url: %s", err)
	}

	if err := validateCreateScanRequest(request); err != nil {
		log.Error("invalid request")
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %s", err)
	}

	log.Info(fmt.Sprintf("Found %d vulnerabilities in scan output", len(request.Results)))

	// strip http/https scheme
	request.Repository = repoUrl.Host + repoUrl.Path

	createTime := timestamppb.Now()

	occurrences := []*grafeas_go_proto.Occurrence{
		createDiscoveryOccurrence(request, discovery_go_proto.Discovered_SCANNING, createTime),
		createDiscoveryOccurrence(request, discovery_go_proto.Discovered_FINISHED_SUCCESS, createTime),
	}

	for _, result := range request.Results {
		vuln := mapScanResultToVulnOccurrence(request, result, createTime)
		occurrences = append(occurrences, vuln)
	}

	log.Debug("calling Rode")
	_, err = tf.rode.BatchCreateOccurrences(ctx, &pb.BatchCreateOccurrencesRequest{
		Occurrences: occurrences,
	})

	if err != nil {
		log.Error("Error creating occurrences", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "error creating occurrences: %s", err)
	}

	log.Info("successfully created occurrences")
	return &empty.Empty{}, nil
}

func createDiscoveryOccurrence(request *v1alpha1.CreateScanRequest, status discovery_go_proto.Discovered_AnalysisStatus, createTime *timestamppb.Timestamp) *grafeas_go_proto.Occurrence {
	return &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: gitResourceUri(request),
		},
		NoteName:   collectorNoteName,
		Kind:       common_go_proto.NoteKind_DISCOVERY,
		CreateTime: createTime,
		Details: &grafeas_go_proto.Occurrence_Discovered{
			Discovered: &discovery_go_proto.Details{
				Discovered: &discovery_go_proto.Discovered{
					ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
					AnalysisStatus:     status,
				}},
		},
	}
}

func mapScanResultToVulnOccurrence(request *v1alpha1.CreateScanRequest, violation *v1alpha1.TfsecScanRuleViolation, createTime *timestamppb.Timestamp) *grafeas_go_proto.Occurrence {
	var b strings.Builder

	writeParagraph(&b, []string{
		violation.Description,
		violation.Impact,
		violation.Resolution,
	})

	return &grafeas_go_proto.Occurrence{
		Resource: &grafeas_go_proto.Resource{
			Uri: gitResourceUri(request),
		},
		NoteName:   collectorNoteName,
		Kind:       common_go_proto.NoteKind_VULNERABILITY,
		CreateTime: createTime,
		Details: &grafeas_go_proto.Occurrence_Vulnerability{
			Vulnerability: &vulnerability_go_proto.Details{
				Type:              "git",
				EffectiveSeverity: mapSeverity(violation.Severity),
				ShortDescription:  b.String(),
				PackageIssue:      mapPackageIssue(request, violation),
			},
		},
	}
}

func gitResourceUri(request *v1alpha1.CreateScanRequest) string {
	return fmt.Sprintf("git://%s@%s", request.Repository, request.CommitId)
}

func validateCreateScanRequest(request *v1alpha1.CreateScanRequest) error {
	if request.CommitId == "" {
		return fmt.Errorf("commit id must be set")
	}

	return nil
}

func writeParagraph(b *strings.Builder, messages []string) {
	for i, message := range messages {
		b.WriteString(message)
		if !strings.HasSuffix(message, ".") {
			b.WriteByte('.')
		}

		if i != len(messages)-1 {
			b.WriteByte(' ')
		}
	}
}

// map tfsec severity levels to Grafeas levels
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
	location := strings.TrimPrefix(violation.Location.Filename, request.ScanDirectory+"/")

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
