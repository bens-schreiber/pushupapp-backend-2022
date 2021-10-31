# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.16-alpine AS builder
WORKDIR /app
COPY ../ .
RUN go mod download
WORKDIR /app/src/main
RUN go build -o restserv


# Run stage
FROM alpine:3.13
WORKDIR /app
COPY --from=builder /app/src/main/restserv .
EXPOSE 8080

CMD "./restserv"
