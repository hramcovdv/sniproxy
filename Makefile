BINARY_VERSION=1.0
BINARY_NAME=gosniproxy

build:
	go build -o $(BINARY_NAME) -ldflags "-X main.version=${BINARY_VERSION}" main.go

run: build
	./${BINARY_NAME}

clean:
	go clean
