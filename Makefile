.PHONY: test fmtcheck vet fmt license coverage generate
MAKEFLAGS += --silent
GOFMT_FILES?=$$(find . -name '*.go' | grep -v proto)
LICENSE_FILES=$$(find -E . -regex '.*\.(go|proto)')

generate:
	docker build ./scripts/generate -t ghcr.io/rode/collector-tfsec/generate:latest
	docker run -it --rm -v $$(pwd):/collector ghcr.io/rode/collector-tfsec/generate:latest

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

license:
	go install github.com/google/addlicense@master
	addlicense -c 'The Rode Authors' $(LICENSE_FILES)

vet:
	go vet ./...

coverage: test
	go tool cover -html=coverage.txt

test: fmtcheck vet
	go test -v ./... -coverprofile=coverage.txt -covermode atomic
