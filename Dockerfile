FROM golang:alpine

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64
    
	
WORKDIR /build

COPY src/go.mod .
COPY src/go.sum .
RUN go mod download

COPY src .

RUN go build -o main .

WORKDIR /dist

RUN cp /build/main .

EXPOSE 80

CMD ["/dist/main"]
