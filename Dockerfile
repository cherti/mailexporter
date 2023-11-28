FROM golang:1.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /mail-exporter

FROM ubuntu:22.04

COPY --from=builder /mail-exporter /mail-exporter

CMD ["/mail-exporter"]
