package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"napscan-be/internal/models"
	"napscan-be/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

type AuthService struct{
	oauthConfig *oauth2.Config
	userRepo    repository.UserRepository
}

func NewAuthService(userRepo repository.UserRepository) *AuthService {
	// Get config from environment with fallback
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
	
	// Fallback to default redirect URL if not set
	if redirectURL == "" {
		redirectURL = "http://localhost:5000/api/auth/google/callback"
	}
	
	// Initialize OAuth2 config for server-side flow
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return &AuthService{
		oauthConfig: config,
		userRepo:    userRepo,
	}
}

func (s *AuthService) upsertGoogleUser(ctx context.Context, incoming *models.User) (*models.User, error) {
	if incoming == nil {
		return nil, errors.New("user cannot be nil")
	}
	if strings.TrimSpace(incoming.Email) == "" {
		return nil, errors.New("email is required")
	}

	// Prefer email as the stable lookup key to avoid duplicates across flows.
	existing, err := s.userRepo.FindByEmail(ctx, incoming.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Reuse existing primary key so Save() updates instead of inserting a new row.
		incoming.ID = existing.ID
	}

	// Align timestamps.
	incoming.UpdatedAt = time.Now()
	if existing == nil {
		incoming.CreatedAt = time.Now()
	} else {
		incoming.CreatedAt = existing.CreatedAt
	}

	if err := s.userRepo.Upsert(ctx, incoming); err != nil {
		return nil, err
	}
	return incoming, nil
}

// GetGoogleLoginURL returns the URL to redirect the user to for Google Login.
// Caller must provide a cryptographically-random state and validate it on callback.
func (s *AuthService) GetGoogleLoginURL(state string) string {
	return s.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account"),)
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

	user := &models.User{
		ID:      googleUser.ID,
		Email:   googleUser.Email,
		Name:    googleUser.Name,
		Picture: googleUser.Picture,
	}

	return s.upsertGoogleUser(ctx, user)
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
	
	user := &models.User{
		ID:      userID,
		Email:   email,
		Name:    name,
		Picture: picture,
	}

	return s.upsertGoogleUser(ctx, user)
}

// GetUserByID retrieves user by ID
func (s *AuthService) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

// GetUserByEmail retrieves user by email
func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
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

func (s *AuthService) GetJWTExpiry(tokenString string) time.Time {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &models.JWTCustomClaims{})
	if err != nil {
		return time.Now().Add(24 * time.Hour)
	}

	claims := token.Claims.(*models.JWTCustomClaims)
	if claims.ExpiresAt != nil {
		return claims.ExpiresAt.Time
	}

	return time.Now().Add(24 * time.Hour)
}
