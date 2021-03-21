package http

import (
	"auth-service/src/jwt"
	"auth-service/src/mongo"
	b64 "encoding/base64"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

func createAccessToken(c *gin.Context) {
	guid := c.PostForm("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Url Param 'Guid' is missing."})
		return
	}

	accessToken, _ := jwt.GenerateAccessToken(guid)
	refreshToken, _ := uuid.NewRandom()
	refreshTokenBase64 := b64.StdEncoding.EncodeToString([]byte(refreshToken.String()))
	refreshTokenBcrypt, _ := bcrypt.GenerateFromPassword([]byte(refreshToken.String()), 10)

	entity := mongo.Token{
		Id:           primitive.NewObjectID(),
		Guid:         guid,
		RefreshToken: string(refreshTokenBcrypt),
		CreatedAt:    time.Now().Local().Unix(),
	}
	err := mongo.PersistToken(entity)
	if err != nil {
		log.Println("Failed to save entity to database for guid " + guid)
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "DB communication failure."})
	} else {
		c.SetCookie("refreshToken", refreshTokenBase64, 2592000, "/api/auth", os.Getenv("APP_DOMAIN"), true, true)
		c.JSON(http.StatusOK, gin.H{"accessToken": accessToken, "refreshToken": refreshTokenBase64})
	}
}

func refreshAccessToken(c *gin.Context) {
	guid := c.PostForm("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Url Param 'Guid' is missing."})
		return
	}

	refreshTokenBase64, err1 := getCookieFromRequest(c)
	if err1 != nil {
		log.Println(err1)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No refresh token in cookies. Unable to refresh access token."})
		return
	}

	refreshTokenBase64Decrypt, err2 := b64.StdEncoding.DecodeString(refreshTokenBase64)
	if err2 != nil {
		log.Println(err2)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Refresh token is corrupted."})
		return
	}

	refreshTokenInMongoDb, err3 := mongo.GetByGuidAndRefreshToken(guid, string(refreshTokenBase64Decrypt))
	if err3 != nil {
		log.Println(err3)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No refresh token in database. Unable to refresh access token."})
		return
	}

	err4 := mongo.RemoveOneRefreshToken(refreshTokenInMongoDb.Id)
	if err4 == nil {
		createAccessToken(c)
	}
}
func removeRefreshToken(c *gin.Context) {
	guid := c.PostForm("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Url Param 'Guid' is missing."})
		return
	}

	refreshTokenBase64, err1 := getCookieFromRequest(c)
	if err1 != nil {
		log.Println(err1)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No refresh token in cookies. Unable to refresh access token."})
		return
	}

	refreshTokenBase64Decrypt, err2 := b64.StdEncoding.DecodeString(refreshTokenBase64)
	if err2 != nil {
		log.Println(err2)
		c.JSON(http.StatusBadRequest, gin.H{"message": "Refresh token is corrupted."})
		return
	}

	refreshTokenInMongoDb, err3 := mongo.GetByGuidAndRefreshToken(guid, string(refreshTokenBase64Decrypt))
	if err3 != nil {
		log.Println(err3)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Refresh token not found"})
		return
	}

	err4 := mongo.RemoveOneRefreshToken(refreshTokenInMongoDb.Id)
	if err4 != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "DB communication failure."})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "You have been logged out successfully."})
	}
}

func removeAllRefreshToken(c *gin.Context) {
	guid := c.PostForm("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Url Param 'Guid' is missing."})
		return
	}

	err := mongo.RemoveAllRefreshTokenByGuid(guid)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "DB communication failure."})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "You have been logged out successfully from all devices."})
	}

}

func getCookieFromRequest(c *gin.Context) (refreshToken string, err error) {
	cookie, err := c.Cookie("refreshToken")
	if err != nil {
		return "", err
	}
	return cookie, err
}

func init() {
	log.Println("Init httpHandler.")
	router := gin.Default()
	router.POST("/api/auth/login", createAccessToken)
	router.POST("/api/auth/refresh-tokens", refreshAccessToken)
	router.POST("/api/auth/logout", removeRefreshToken)
	router.POST("/api/auth/logoutEverywhere", removeAllRefreshToken)
	defer mongo.CloseConnection()
	log.Println("Starting web-service.")
	_ = router.Run()
}
