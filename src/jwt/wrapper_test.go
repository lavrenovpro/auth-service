package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {
	_, err := GenerateAccessToken("someGuid")
	assert.NoError(t, err)
}
