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
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-tfsec/mocks"
	"github.com/rode/collector-tfsec/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = Describe("Server", func() {
	var (
		ctx             = context.Background()
		rodeClient      *mocks.FakeRodeClient
		server          *tfsecCollector
		severityMapping = map[string]vulnerability_go_proto.Severity{
			"INFO":    vulnerability_go_proto.Severity_MINIMAL,
			"WARNING": vulnerability_go_proto.Severity_MEDIUM,
			"ERROR":   vulnerability_go_proto.Severity_HIGH,
		}
	)

	BeforeEach(func() {
		rodeClient = &mocks.FakeRodeClient{}

		server = NewTfsecCollector(logger, rodeClient)
	})

	Context("CreateScan", func() {
		var (
			actualError         error
			request             *v1alpha1.CreateScanRequest
			expectedResourceUri string
		)

		BeforeEach(func() {
			repoName := fake.DomainName() + "/" + fake.Word()
			request = &v1alpha1.CreateScanRequest{
				CommitId:   fake.LetterN(10),
				Repository: "https://" + repoName,
				Results:    []*v1alpha1.TfsecScanRuleViolation{},
			}

			expectedResourceUri = fmt.Sprintf("git://%s@%s", repoName, request.CommitId)

			for i := 0; i < fake.Number(2, 5); i++ {
				request.Results = append(request.Results, randomTfsecScanRuleViolation())
			}
		})

		JustBeforeEach(func() {
			_, actualError = server.CreateScan(ctx, request)
		})

		When("the scan is successful", func() {
			It("should not return an error", func() {
				Expect(actualError).ToNot(HaveOccurred())
			})

			It("should create two discovery occurrences", func() {
				expectedLength := 2 + len(request.Results)
				Expect(rodeClient.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(actualRequest.Occurrences).To(HaveLen(expectedLength))

				for i := 0; i < 2; i++ {
					occurrence := actualRequest.Occurrences[i]

					discovered := occurrence.GetDiscovered().Discovered
					expectedStatus := discovery_go_proto.Discovered_SCANNING

					if i == 1 {
						expectedStatus = discovery_go_proto.Discovered_FINISHED_SUCCESS
					}
					Expect(occurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
					Expect(discovered.ContinuousAnalysis).To(Equal(discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED))
					Expect(discovered.AnalysisStatus).To(Equal(expectedStatus))
				}
			})

			It("should create a vulnerability for each scan result", func() {
				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				for i := 2; i < len(request.Results)+2; i++ {
					occurrence := actualRequest.Occurrences[i]

					Expect(occurrence.Resource.Uri).To(Equal(fmt.Sprintf(expectedResourceUri)))
					Expect(occurrence.NoteName).To(Equal("projects/rode/notes/tfsec"))
					Expect(occurrence.CreateTime.IsValid()).To(BeTrue())

					scanResult := request.Results[i-2]
					expectedSeverity := severityMapping[scanResult.Severity]
					expectedDescription := strings.Join([]string{
						scanResult.Description,
						scanResult.Impact,
						scanResult.Resolution,
					}, " ")
					vuln := occurrence.GetVulnerability()

					Expect(occurrence.Kind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))
					Expect(vuln.Type).To(Equal("git"))
					Expect(vuln.EffectiveSeverity).To(Equal(expectedSeverity))
					Expect(vuln.ShortDescription).To(Equal(expectedDescription))

					Expect(vuln.PackageIssue).To(HaveLen(1))
					actualLocation := vuln.PackageIssue[0].AffectedLocation
					expectedDocsLink := fmt.Sprintf("https://tfsec.dev/docs/%s/%s/", scanResult.RuleProvider, scanResult.RuleId)

					Expect(actualLocation.CpeUri).To(Equal(expectedDocsLink))
					Expect(actualLocation.Package).To(Equal(scanResult.Location.Filename))
					Expect(actualLocation.Version.Name).To(Equal(scanResult.Location.Filename))
					Expect(actualLocation.Version.Kind).To(Equal(package_go_proto.Version_NORMAL))
				}
			})

			It("should use the same timestamp for all occurrences", func() {
				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)
				expectedTimestamp := actualRequest.Occurrences[0].CreateTime

				Expect(expectedTimestamp.IsValid()).To(BeTrue())
				for i := 1; i < len(actualRequest.Occurrences)-1; i++ {
					Expect(actualRequest.Occurrences[i].CreateTime).To(Equal(expectedTimestamp))
				}
			})
		})

		When("no issues are found", func() {
			BeforeEach(func() {
				request.Results = []*v1alpha1.TfsecScanRuleViolation{}
			})

			It("should create two discovery occurrences", func() {
				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(actualRequest.Occurrences).To(HaveLen(2))
			})
		})

		When("a scan directory is passed", func() {
			var expectedFilename string
			BeforeEach(func() {
				expectedFilename = fake.Word()
				request.ScanDirectory = fake.Word()
				violation := randomTfsecScanRuleViolation()
				violation.Location.Filename = filepath.Join(request.ScanDirectory, expectedFilename)
				request.Results = []*v1alpha1.TfsecScanRuleViolation{
					violation,
				}
			})


			It("should remove the directory from the source code locations", func() {
				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)
				vuln := actualRequest.Occurrences[2].GetVulnerability()

				Expect(vuln.PackageIssue[0].AffectedLocation.Package).To(Equal(expectedFilename))
				Expect(vuln.PackageIssue[0].AffectedLocation.Version.Name).To(Equal(expectedFilename))
			})
		})

		When("the scan result description doesn't end in a period", func() {
			var expectedViolationDescription string

			BeforeEach(func() {
				violation := randomTfsecScanRuleViolation()
				violation.Description = fake.Word()
				request.Results = []*v1alpha1.TfsecScanRuleViolation{
					violation,
				}

				expectedViolationDescription = strings.Join([]string{
					violation.Description + ".",
					violation.Impact,
					violation.Resolution,
				}, " ")
			})

			It("should end the description with a period", func() {
				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(actualRequest.Occurrences[2].GetVulnerability().ShortDescription).To(Equal(expectedViolationDescription))
			})
		})

		When("an unrecognized severity is passed", func() {
			BeforeEach(func() {
				violation := randomTfsecScanRuleViolation()
				violation.Severity = fake.Word()
				request.Results = []*v1alpha1.TfsecScanRuleViolation{
					violation,
				}
			})

			It("should set the unspecified severity on the vulnerability occurrence", func() {
				_, actualRequest, _ := rodeClient.BatchCreateOccurrencesArgsForCall(0)

				Expect(actualRequest.Occurrences[2].GetVulnerability().Severity).To(Equal(vulnerability_go_proto.Severity_SEVERITY_UNSPECIFIED))
			})
		})

		When("an error occurs creating occurrences", func() {
			BeforeEach(func() {
				rodeClient.BatchCreateOccurrencesReturns(nil, errors.New(fake.Word()))
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
				Expect(getGRPCStatusFromError(actualError).Code()).To(Equal(codes.Internal))
			})
		})

		When("commit id is empty", func() {
			BeforeEach(func() {
				request.CommitId = ""
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
				Expect(getGRPCStatusFromError(actualError).Code()).To(Equal(codes.InvalidArgument))
			})
		})

		When("repository is empty", func() {
			BeforeEach(func() {
				request.Repository = ""
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
				Expect(getGRPCStatusFromError(actualError).Code()).To(Equal(codes.InvalidArgument))
			})
		})

		When("repository url is invalid", func() {
			BeforeEach(func() {
				request.Repository = fake.Word()
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
				Expect(getGRPCStatusFromError(actualError).Code()).To(Equal(codes.InvalidArgument))
			})
		})
	})
})

func getGRPCStatusFromError(err error) *status.Status {
	s, ok := status.FromError(err)
	Expect(ok).To(BeTrue(), "Expected error to be a gRPC status")

	return s
}

func randomTfsecScanRuleViolation() *v1alpha1.TfsecScanRuleViolation {
	return &v1alpha1.TfsecScanRuleViolation{
		RuleId:       fake.Word(),
		RuleProvider: fake.RandomString([]string{"aws", "azure", "gcp"}),
		Location: &v1alpha1.SourceCodeLocation{
			Filename: fake.Word(),
		},
		Description: fake.Sentence(fake.Number(2, 5)),
		Impact:      fake.Sentence(fake.Number(2, 5)),
		Resolution:  fake.Sentence(fake.Number(2, 5)),
		Severity:    fake.RandomString([]string{"INFO", "WARNING", "ERROR"}),
	}
}
