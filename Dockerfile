FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o midun-api main.go

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /build/midun-api .
COPY --from=builder /build/zkp-circuit/verification.key ./zkp-circuit/verification.key
COPY --from=builder /build/zokrates /usr/local/bin/zokrates
RUN chmod +x /usr/local/bin/zokrates
EXPOSE 8090
CMD ["./midun-api"]
