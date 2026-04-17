FROM golang:1.26-alpine3.23 AS build
WORKDIR /src/
COPY . .
RUN go build -v -o gosniproxy main.go

FROM alpine:3.23
COPY --from=build /src/gosniproxy /bin/gosniproxy
EXPOSE 443/tcp
ENTRYPOINT ["/bin/gosniproxy"]
