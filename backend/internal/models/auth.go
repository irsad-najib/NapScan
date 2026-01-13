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
	ID        string    `json:"id" bson:"id"`
	Email     string    `json:"email" bson:"email"`
	Name      string    `json:"name" bson:"name"`
	Picture   string    `json:"picture,omitempty" bson:"picture,omitempty"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

type JWTCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}
