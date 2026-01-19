package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type GoogleAuthRequest struct {
	IDToken string `json:"id_token"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	User        User   `json:"user"`
}

type User struct {
	ID        string    `json:"id" gorm:"primaryKey;type:varchar(191)"`
	Email     string    `json:"email" gorm:"type:varchar(191);uniqueIndex"`
	Name      string    `json:"name" gorm:"type:varchar(255)"`
	Picture   string    `json:"picture,omitempty" gorm:"type:text"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type JWTCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}
