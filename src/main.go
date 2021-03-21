package main

import (
	_ "auth-service/src/http"
	_ "auth-service/src/jwt"
	_ "auth-service/src/mongo"
	"log"
)

func main() {
	log.Println("auth-service is starting...")
}
