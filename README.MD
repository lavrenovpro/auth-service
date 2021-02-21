# Building and running auth-service 

## docker-compose stack with mongo replica set
```shell
git clone https://github.com/lavrenovpro/auth-service.git
cd auth-service
docker build -t auth-service .
docker-compose up -d
docker exec -it localmongo1 mongo  --quiet --eval "rs.initiate(\
    {\
        _id: 'rs0',\
        members: [\
            {_id: 0, host: \"mongo1:27017\", priority: 1},\
            {_id: 1, host: \"mongo2:27017\", priority: 0.5},\
            {_id: 2, host: \"mongo3:27017\", priority: 0.5}\
        ]\
    }\
)"
```

# Curl examples

## Get tokens
```shell
curl --location --request POST 'localhost:8080/api/auth/login' --form 'guid="123"'
```

## Refresh tokens
```shell
curl --location --request POST 'localhost:8080/api/auth/refresh-tokens' \
--header 'Cookie: refreshToken=Yzg1ZWMzODUtOTRiMy00NDE2LWIwNjctNmQwYTAzMDhlNGE1; Path=/api/auth; Domain=localhost; Max-Age=2592000; HttpOnly; Secure' \
--form 'guid="123"'
```

## Remove token

```shell
curl --location --request POST 'localhost:8080/api/auth/logout' \
--header 'Cookie: refreshToken=ODMxNWVjMzEtYWRhZS00YjlmLWJkOWUtYjQyZjU2OGU0OTc5; Path=/api/auth; Domain=localhost; Max-Age=2592000; HttpOnly; Secure' \
--form 'guid="123"'
```

## Remove all tokens
```shell
curl --location --request POST 'localhost:8080/api/auth/logoutEverywhere' \
--form 'guid="123"'
```

