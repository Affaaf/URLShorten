package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"Go_CRUD.com/m/controllers"
	"Go_CRUD.com/m/initializers"
	"Go_CRUD.com/m/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
}

func main() {
	r := gin.Default()
	r.POST("/posts", controllers.PostsCreate)
	r.GET("/posts", controllers.PostsIndex)
	r.GET("/posts/:id", controllers.PostShow)
	r.PUT("/posts/:id", controllers.PostUpdate)
	r.DELETE("/posts/:id", controllers.PostDelete)
	r.POST("/login", controllers.Login)
	r.POST("/signup", controllers.Signup)
	r.Use(AuthMiddleware())
	r.POST("/shorten", controllers.CreateShortURL)
	r.GET("/redirect_actualUrl/:id", controllers.RedirectToActualURL)
	r.GET("/retrieve_urls", controllers.RetrieveURLS)

	r.Run()

}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeader := c.GetHeader("Authorization")
		fmt.Print("234233333333333333", authorizationHeader)
		// Split the Authorization header to extract the token
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) != 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Malformed token"})
			c.Abort()
			return
		}
		tokenString := bearerToken[1] // Extract the actual token from the "Bearer <token>" format
		token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Make sure that the token method conforms to "SigningMethodHMAC"
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("secret"), nil
		})

		if _, ok := token.Claims.(*models.JWTClaims); !ok || !token.Valid {
			var validationError *jwt.ValidationError
			if errors.As(err, &validationError) {
				if validationError.Errors&jwt.ValidationErrorMalformed != 0 {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Malformed token"})
				} else if validationError.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is either expired or not active yet"})
				} else {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not valid"})
				}
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not valid"})
			}
			c.Abort()
			return
		}

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims := token.Claims.(*models.JWTClaims)
		c.Set("id", claims.UserID)

		c.Next()
	}
}
