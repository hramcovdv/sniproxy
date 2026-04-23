BINARY_VERSION=1.2.2
BINARY_NAME=gosniproxy

run:
	go run .

test:
	go test ./...

clean:
	go clean

build:
	go build -o $(BINARY_NAME) -ldflags "-X main.version=${BINARY_VERSION}"

install: build
	cp $(BINARY_NAME) /usr/sbin/$(BINARY_NAME)
	cp $(BINARY_NAME).service /etc/systemd/system/$(BINARY_NAME).service
