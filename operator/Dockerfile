FROM golang:1.20 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/vat-operator ./cmd/vat-operator

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/vat-operator /vat-operator
USER nonroot:nonroot
ENTRYPOINT ["/vat-operator"]
