VERSION=0.0.4
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} "

all: check_ssl_certificate2

.PHONY: check_ssl_certificate2

check_ssl_certificate2: main.go certificate.go
	go build $(LDFLAGS) -o check_ssl_certificate2 certificate.go main.go

linux: main.go certificate.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o check_ssl_certificate2 certificate.go main.go

check:
	go test ./...

fmt:
	go fmt ./...
