FROM golang:1.25-alpine AS build
WORKDIR /src/
COPY . .
RUN go mod download && go mod verify && go build -v -o gosniproxy main.go

FROM alpine:3.22
COPY --from=build /src/gosniproxy /bin/gosniproxy
EXPOSE 443/tcp
ENTRYPOINT ["/bin/gosniproxy"]
