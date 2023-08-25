package controllers

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"

	"Go_CRUD.com/m/initializers"
	"Go_CRUD.com/m/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	"time"
)

type body struct {
	Body  string
	Title string
}

func PostsCreate(c *gin.Context) {
	var requestBody body
	if err := c.Bind(&requestBody); err != nil {
		// Handle the error (e.g., return an error response)
		return
	}

	post := models.Post{Title: requestBody.Title, Body: requestBody.Body}
	result := initializers.DB.Create(&post)

	if result.Error != nil {
		c.Status(400)
		return
	}
	c.JSON(200, gin.H{
		"post": post,
	})
}

func PostsIndex(c *gin.Context) {

	// get post
	var posts []models.Post
	initializers.DB.Find(&posts)

	// response
	c.JSON(200, gin.H{
		"post": posts,
	})

}

func PostShow(c *gin.Context) {

	// get post
	id := c.Param("id")
	var post models.Post
	initializers.DB.First(&post, id)

	// response
	c.JSON(200, gin.H{
		"post": post,
	})

}

func PostUpdate(c *gin.Context) {

	// get post
	// type body struct {
	// 	Body  string
	// 	Title string
	// }
	id := c.Param("id")
	var post models.Post
	initializers.DB.First(&post, id)

	var requestBody body
	if err := c.Bind(&requestBody); err != nil {
		// Handle the error (e.g., return an error response)
		return
	}
	print("fghjkl--------", requestBody.Title, "\nfghjk88888", requestBody.Body, "\n")
	initializers.DB.Model(&post).Updates(models.Post{Title: requestBody.Title, Body: requestBody.Body})
	// fmt.Println("dfcgbjhnkmjhfgxc", post)
	// response
	c.JSON(200, gin.H{
		"post": post,
	})

}

func PostDelete(c *gin.Context) {

	// get post
	id := c.Param("id")

	initializers.DB.Delete(&models.Post{}, id)

	// response
	c.Status(200)

}

func GetCurrentUser(c *gin.Context) (models.User, error) {
	var user models.User
	userID, exists := c.Get("id")
	if !exists {
		return user, fmt.Errorf("No user ID found in the context")
	}

	if err := initializers.DB.First(&user, userID).Error; err != nil {
		return user, fmt.Errorf("Failed to get user details")
	}

	return user, nil
}

type JWTData struct {
	jwt.StandardClaims
	CustomClaims map[string]interface{} // Use interface{} to handle various custom claim types
}

func CreateShortURL(c *gin.Context) {
	fmt.Println(c.Request.Body)
	type urls struct {
		ActualURL string
	}
	var requestBody urls
	// if err := c.Bind(&requestBody); err != nil {
	// 	// Handle the error (e.g., return an error response)
	// 	c.JSON(400, gin.H{"error": "Invalid request"})
	// 	return
	// }

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Parse the JWT token from the request header
	// tokenString := c.GetHeader("Authorization")
	// if tokenString == "" {
	// 	c.JSON(401, gin.H{"error": "Missing authorization token"})
	// 	return
	// }

	// // Parse and validate the JWT token
	// claims := &JWTData{}
	// _, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
	// 	return secretKey, nil
	// })
	// if err != nil {
	// 	if validationErr, ok := err.(*jwt.ValidationError); ok {
	// 		if validationErr.Errors&jwt.ValidationErrorMalformed != 0 {
	// 			c.JSON(401, gin.H{"error": "Token is malformed"})
	// 			return
	// 		} else if validationErr.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
	// 			c.JSON(401, gin.H{"error": "Token is either expired or not active yet"})
	// 			return
	// 		}
	// 	}
	// 	c.JSON(401, gin.H{"error": "Invalid token"})
	// 	return
	// }
	// fmt.Println("777777777777777", claims)
	// Rest of your URL shortening logic
	// ...

	var existingURL models.URLShorten
	if err := initializers.DB.Where("actual_url = ?", requestBody.ActualURL).First(&existingURL).Error; err == nil {
		c.JSON(200, gin.H{"url": "http://127.0.0.1:3030/redirect_actualUrl/" + existingURL.ShortenURL})
		return
	}

	// Calculate a unique identifier for the URL using a hash
	hash := sha1.New()
	hash.Write([]byte(requestBody.ActualURL))
	hashValue := base64.URLEncoding.EncodeToString(hash.Sum(nil))[:6]
	// ok := claims.CustomClaims["UserID"]
	// userIDFloat, ok := claims.CustomClaims["user_id"].(float64)
	// fmt.Println("55555555", "4444444444-----", ok)
	currentUser, _ := GetCurrentUser(c)

	// You can access the user ID from the retrieved user object
	// userID := user.ID
	fmt.Println("\n\n\n\n\n\n\n\n\n00")
	fmt.Println(currentUser)
	url := models.URLShorten{ActualURL: requestBody.ActualURL, ShortenURL: hashValue, UserId: currentUser.ID}

	shortenURL := initializers.DB.Create(&url)

	if shortenURL.Error != nil {
		c.JSON(500, gin.H{"error": "Failed to create short URL"})
		return
	}

	c.JSON(200, gin.H{
		"url": "http://127.0.0.1:3030/redirect_actualUrl/" + url.ShortenURL,
	})
}

func RedirectToActualURL(c *gin.Context) {

	// tokenString := c.GetHeader("Authorization")
	// if tokenString == "" {
	// 	c.JSON(401, gin.H{"error": "Missing authorization token"})
	// 	return
	// }

	// // Parse and validate the JWT token
	// claims := &JWTData{}
	// _, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
	// 	return secretKey, nil
	// })
	// if err != nil {
	// 	if validationErr, ok := err.(*jwt.ValidationError); ok {
	// 		if validationErr.Errors&jwt.ValidationErrorMalformed != 0 {
	// 			c.JSON(401, gin.H{"error": "Token is malformed"})
	// 			return
	// 		} else if validationErr.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
	// 			c.JSON(401, gin.H{"error": "Token is either expired or not active yet"})
	// 			return
	// 		}
	// 	}
	// 	c.JSON(401, gin.H{"error": "Invalid token"})
	// 	return
	// }

	shortid := c.Param("id")

	// Retrieve the actual URL from the database using the short URL
	var url models.URLShorten
	if err := initializers.DB.Where("shorten_url = ?", shortid).First(&url).Error; err != nil {
		c.JSON(404, gin.H{"error": "Short URL not found"})
		return
	}

	c.Redirect(http.StatusMovedPermanently, url.ActualURL)

}

func Signup(c *gin.Context) {

	type data struct {
		Username string
		Email    string
		Password string
	}

	var requestBody data
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		// Handle the error (e.g., return an error response)
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Check if username already exists
	var existingUser models.User
	if err := initializers.DB.Where("username = ?", requestBody.Username).First(&existingUser).Error; err == nil {
		c.JSON(409, gin.H{"error": "Username already exists"})
		return
	}

	// Create the user in the database
	user := models.User{Username: requestBody.Username, Email: requestBody.Email, Password: requestBody.Password}

	if err := initializers.DB.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(201, gin.H{"message": "User created successfully"})
}

var secretKey = []byte("your-secret-key")

type CustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.StandardClaims
}

func GenerateJWTAccessToken(userId string, email string) (string, error) {
	claims := CustomClaims{
		UserID: userId,
		Email:  email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 10).Unix(), // Token lifetime 10 hour
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)

	return tokenString, err
}

// func Login(c *gin.Context) {
// 	type credentials struct {
// 		Username string
// 		Password string
// 	}

// 	var creds credentials
// 	if err := c.ShouldBindJSON(&creds); err != nil {
// 		c.JSON(400, gin.H{"error": "Invalid request"})
// 		return
// 	}

// 	var user models.User
// 	if err := initializers.DB.Where("username = ?", creds.Username).First(&user).Error; err != nil {
// 		c.JSON(404, gin.H{"error": "User not found"})
// 		return
// 	}

// 	if user.Password != creds.Password {
// 		c.JSON(401, gin.H{"error": "Authentication failed"})
// 		return
// 	}

// 	// Generate JWT access token
// 	token, err := GenerateJWTAccessToken(fmt.Sprintf("%d", user.ID), user.Email)
// 	if err != nil {
// 		c.JSON(500, gin.H{"error": "Failed to generate token"})
// 		return
// 	}

// 	c.JSON(200, gin.H{"message": "Login successful", "token": token})
// }

func Login(c *gin.Context) {
	var user struct {
		Username string `form:"username"`
		Password string `form:"password"`
	}

	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var foundUser models.User
	initializers.DB.Where("username = ?", user.Username).First(&foundUser)

	claims := models.JWTClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
		UserID: foundUser.ID,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func RetrieveURLS(c *gin.Context) {
	// Retrieve the current user
	currentUser, err := GetCurrentUser(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var urls []models.URLShorten

	// Find all URLs associated with the current user's ID
	if err := initializers.DB.Where("user_id = ?", currentUser.ID).Find(&urls).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve URLs"})
		return
	}

	// Response
	c.JSON(200, gin.H{
		"urls": urls,
	})
}
