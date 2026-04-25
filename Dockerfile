FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o midun-api main.go

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/midun-api .
COPY --from=builder /build/zkp-circuit/verification.key ./zkp-circuit/verification.key
COPY --from=builder /build/zokrates /usr/local/bin/zokrates
COPY --from=builder /build/vc-private.pem .
COPY --from=builder /build/vc-public.pem .
RUN chmod +x /usr/local/bin/zokrates
RUN chmod 600 /app/vc-private.pem
EXPOSE 8090
CMD ["./midun-api"]
