# Stage 1
FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# main app
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/app ./cmd/http/main.go
# migrations
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/migrate ./cmd/migrations/main.go

# Stage 2
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /usr/local/bin/app /usr/local/bin/app
COPY --from=builder /usr/local/bin/migrate /usr/local/bin/migrate
COPY . .

# Run migrations and start the main application
CMD /bin/sh -c "/usr/local/bin/migrate --migrate=up && /usr/local/bin/app"