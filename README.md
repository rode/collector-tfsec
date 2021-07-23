# collector-tfsec

Send the result of [tfsec](https://tfsec.dev/) scans to [Rode](https://github.com/rode/rode). 

## Local Development

To work with the collector locally, you need a running instance of Rode and its dependencies.

1. Run the collector with `go run main.go --rode-host=localhost:50051 --rode-insecure-disable-transport-security`
    - If your Rode instance is configured for auth, include the `--proxy-auth` flag.
1. Send a scan to the collector:
   ```
   $ cat scan.json
   {
      "commitId": "123",
      "repository": "https://github.com/rode/demo",
      "scanDirectory": "/absolute/path/to/scan/root",
      "results": [
         {
            "rule_id": "GEN001",
            // ...
         }
      ]
   }
   $ curl -H 'Content-Type: application/json' -d @scan.json http://localhost:8083/v1alpha1/scans
   
   ```
1. To run the fmt check and tests, use `make test`
1. To add the required license headers, run `make license`
