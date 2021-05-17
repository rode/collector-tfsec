# new-collector-template

Boilerplate for creating new collectors.

## Usage

1. Hit the "Use this template" button to create a new repository from the template.
1. Update the go mod file with the new root module: `go mod edit -module "github.com/rode/$MY_COLLECTOR"`.
1. Find and replace any usages of the following with your collector name:
    1. new-collector-template
    1. newCollectorTemplate 
    1. new_collector_template
1. Delete or modify the proto files under `proto/v1alpha1`.
   - Remove any generated code under `proto`
1. Run `make generate` to update the generated server code. 
1. Update the `server` package to implement the new gRPC server interface.
1. Update `main.go` to reference the new server and handler code
1. Pick an unallocated set of ports and update the `config` package to replace the defaults for `--http-port` and `--grpc-port`. 
    - The `config` tests will need to be updated as well

## What's Included

- Example collector endpoint
- Flag configuration under `config`
- Boilerplate for creating a gRPC server & gRPC gateway in the `server` package and `main.go` 
- Dockerfile
- Unit tests, including a mock for the Rode client. 
- Protobuf code generation
- [GoReleaser](https://goreleaser.com/) config  
- Makefile targets for common tasks
    - `coverage`: Runs the tests and opens a browser window with the code coverage report
    - `fmt`: Runs `gofmt`
    - `fmtcheck`: Checks to see if `gofmt` needs to run
    - `generate`: Generates client and server code from the protobuf definitions    
    - `license`: Runs `addlicense` to populate license headers on source code
    - `mocks`: Generates a mock for the Rode client    
    - `run`: Run the collector locally    
    - `test`: Runs unit tests
    - `vet`: Runs `go vet`
