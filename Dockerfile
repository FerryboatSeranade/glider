# Build Stage
FROM golang:1.24-alpine AS build-env
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN apk --no-cache add git \
    && go build -v -ldflags "-s -w"

# Final Stage
FROM alpine
RUN apk -U upgrade --no-cache \
    && apk --no-cache add ca-certificates tzdata \
    && mkdir -p /etc/rules.d /etc/glider-cache /etc/glider-certs \
    && chown -R 1000:1000 /etc/rules.d /etc/glider-cache /etc/glider-certs
COPY --from=build-env /src/glider /usr/local/bin/glider
USER 1000
ENTRYPOINT ["glider"]
