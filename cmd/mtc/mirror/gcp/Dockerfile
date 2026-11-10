# The golang images set GOTOOLCHAIN=local, so this Go version should match the toolchain directive in go.mod.
FROM golang:1.26.10-alpine3.24@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS builder

ARG GOFLAGS="-trimpath -buildvcs=false -buildmode=exe"
ENV GOFLAGS=$GOFLAGS

# Move to working directory /build
WORKDIR /build

# Copy and download dependencies using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -o bin/mtc-mirror-gcp ./cmd/mtc/mirror/gcp

# Build release image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

COPY --from=builder /build/bin/mtc-mirror-gcp /bin/mtc-mirror-gcp

# The server only needs network access, so run it as an unprivileged user.
USER 65534:65534

ENTRYPOINT ["/bin/mtc-mirror-gcp"]
