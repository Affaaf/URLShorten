package models

import (
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

type Post struct {
	gorm.Model
	Title string
	Body  string
}

type URLShorten struct {
	gorm.Model
	ActualURL  string
	ShortenURL string
	UserId     uint
	User       User `gorm:"foreignKey:UserId;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Email    string
	Password string
}
type JWTClaims struct {
	jwt.StandardClaims
	UserID uint `json:"user_id"`
}
