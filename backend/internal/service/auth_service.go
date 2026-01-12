package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"napscan-be/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

type AuthService struct{
	oauthConfig *oauth2.Config
}

func NewAuthService() *AuthService {
	// Initialize OAuth2 config for server-side flow
	config := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return &AuthService{
		oauthConfig: config,
	}
}

// GetGoogleLoginURL returns the URL to redirect the user to for Google Login
func (s *AuthService) GetGoogleLoginURL() string {
	// State should be randomized in production to prevent CSRF
	return s.oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
}

// HandleGoogleCallback exchanges code for token and retrieves user info
func (s *AuthService) HandleGoogleCallback(ctx context.Context, code string) (*models.User, error) {
	token, err := s.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	// Use token to get user info
	client := s.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get user info from google")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.Unmarshal(data, &googleUser); err != nil {
		return nil, err
	}

	return &models.User{
		ID:      googleUser.ID,
		Email:   googleUser.Email,
		Name:    googleUser.Name,
		Picture: googleUser.Picture,
	}, nil
}


// VerifyGoogleToken validates the Google ID token and extracts user info (Client-Side Flow)
func (s *AuthService) VerifyGoogleToken(ctx context.Context, tokenString string) (*models.User, error) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	
	payload, err := idtoken.Validate(ctx, tokenString, clientID)
	if err != nil {
		return nil, err
	}

	userID := payload.Subject
	email, _ := payload.Claims["email"].(string)
	name, _ := payload.Claims["name"].(string)
	picture, _ := payload.Claims["picture"].(string)
	
	return &models.User{
		ID:      userID,
		Email:   email,
		Name:    name,
		Picture: picture,
	}, nil
}

// GenerateJWT creates a new access token for the backend
func (s *AuthService) GenerateJWT(user *models.User) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev-secret-key-change-in-prod"
	}

	claims := models.JWTCustomClaims{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "napscan-be",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
