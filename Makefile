.PHONY: build test lint run clean install

VERSION  := 0.1.0
BINARY   := mcpsense
LDFLAGS  := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/mcpsense/

test:
	go test ./... -v -cover

lint:
	golangci-lint run ./...

run:
	go run ./cmd/mcpsense/ scan $(TARGET)

clean:
	rm -rf bin/

install:
	go install $(LDFLAGS) ./cmd/mcpsense/
