FROM golang:1.16.0-alpine3.13 AS build
WORKDIR /src
COPY /src .

RUN go mod vendor
RUN go build -o /out/auth-service .
FROM alpine AS bin
COPY --from=build /out/auth-service /usr/bin

EXPOSE 8080

CMD ["auth-service"]
