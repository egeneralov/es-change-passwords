FROM golang:1.16.3

RUN apt-get update -q && apt-get install -yq ca-certificates

ENV \
  GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64

WORKDIR /go/src/github.com/egeneralov/es-change-passwords
ADD go.mod go.sum /go/src/github.com/egeneralov/es-change-passwords/
RUN go mod download

ADD . .

RUN go build -v -installsuffix cgo -ldflags="-w -s" -o /go/bin/es-change-passwords cmd/main.go


FROM debian:buster

RUN apt-get update -q && apt-get install -yq ca-certificates
USER nobody
ENV PATH='/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
CMD /go/bin/es-change-passwords

COPY --from=0 /go/bin /go/bin
