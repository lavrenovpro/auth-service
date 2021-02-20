package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {
	jwtWrapper := JwtWrapper{
		SecretKey:       "SomeSecretKey",
		Issuer:          "AuthService",
		ExpirationHours: 24,
	}

	_, err := jwtWrapper.generateAccessToken("someGuid")
	assert.NoError(t, err)
}
