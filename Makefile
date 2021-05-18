.PHONY: test fmtcheck vet fmt license coverage mocks generate
MAKEFLAGS += --silent
GOFMT_FILES?=$$(find . -name '*.go' | grep -v proto)
LICENSE_FILES=$$(find -E . -regex '.*\.(go|proto)')

GO111MODULE=on

generate:
	docker build ./scripts/generate -t ghcr.io/rode/collector-tfsec/generate:latest
	docker run -it --rm -v $$(pwd):/collector ghcr.io/rode/collector-tfsec/generate:latest

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

license:
	addlicense -c 'The Rode Authors' $(LICENSE_FILES)

vet:
	go vet ./...

coverage: test
	go tool cover -html=coverage.txt

mocks:
	go install github.com/maxbrunsfeld/counterfeiter/v6@v6.4.1
	COUNTERFEITER_NO_GENERATE_WARNING="true" go generate ./...

test: fmtcheck vet
	go test -v ./... -coverprofile=coverage.txt -covermode atomic
