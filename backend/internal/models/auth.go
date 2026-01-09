package models

import "github.com/golang-jwt/jwt/v5"

type GoogleAuthRequest struct {
	IDToken string `json:"id_token"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	User        User   `json:"user"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Picture string `json:"picture"`
}

type JWTCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	jwt.RegisteredClaims
}
