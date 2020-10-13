init:
	GO111MODULE=on go mod download
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.31.0

lint:
	GO111MODULE=on golangci-lint run ./...

test:
	GO111MODULE=on go test ./...

test-coverage:
	GO111MODULE=on go test -coverprofile=c.out ./... >& /dev/null
	go tool cover -func=c.out
