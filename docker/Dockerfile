FROM golang:1.23.2 AS builder

WORKDIR /app

RUN mkdir cmd/ internal/ vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY vendor/ ./vendor/
COPY Makefile go.mod go.sum ./

RUN go mod download
RUN make

FROM scratch

COPY --from=builder /app/cmd/veil/veil /

CMD ["/veil"]
