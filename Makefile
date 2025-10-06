BINARY_VERSION=0.1.1
BINARY_NAME=sniproxy

build:
	go build -o $(BINARY_NAME) -ldflags "-X main.version=${BINARY_VERSION}" main.go

run: build
	./${BINARY_NAME}

clean:
	go clean
