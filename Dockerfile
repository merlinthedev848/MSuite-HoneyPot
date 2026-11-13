FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o msuite-honeypot ./cmd/msuite-honeypot

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/msuite-honeypot /usr/local/bin/msuite-honeypot

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/msuite-honeypot"]
