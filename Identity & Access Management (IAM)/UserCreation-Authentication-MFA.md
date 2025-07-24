package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"context"
)

// User represents a user in the system
type User struct {
	ID                string    `json:"id" db:"id"`
	Username          string    `json:"username" db:"username"`
	Email             string    `json:"email" db:"email"`
	PasswordHash      string    `json:"-" db:"password_hash"`
	MFAEnabled        bool      `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret         string    `json:"-" db:"mfa_secret"`
	MFABackupCodes    []string  `json:"-" db:"mfa_backup_codes"`
	EmailVerified     bool      `json:"email_verified" db:"email_verified"`
	AccountLocked     bool      `json:"account_locked" db:"account_locked"`
	FailedLoginCount  int       `json:"-" db:"failed_login_count"`
	LastLogin         time.Time `json:"last_login" db:"last_login"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// CreateUserRequest represents a user creation request
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// EnableMFAResponse represents the response when enabling MFA
type EnableMFAResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

// UserService handles all user-related operations
type UserService struct {
	db          *sql.DB
	redis       *redis.Client
	jwtSecret   []byte
	serviceName string
}

// NewUserService creates a new user service
func NewUserService(db *sql.DB, redis *redis.Client, jwtSecret []byte) *UserService {
	return &UserService{
		db:          db,
		redis:       redis,
		jwtSecret:   jwtSecret,
		serviceName: "AWS-Clone-IAM",
	}
}

// Initialize creates the necessary database tables
func (us *UserService) Initialize() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		mfa_enabled BOOLEAN DEFAULT FALSE,
		mfa_secret TEXT,
		mfa_backup_codes TEXT[], -- Array of backup codes
		email_verified BOOLEAN DEFAULT FALSE,
		account_locked BOOLEAN DEFAULT FALSE,
		failed_login_count INTEGER DEFAULT 0,
		last_login TIMESTAMP WITH TIME ZONE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);

	CREATE TABLE IF NOT EXISTS user_sessions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		ip_address INET,
		user_agent TEXT,
		revoked BOOLEAN DEFAULT FALSE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON user_sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);

	-- Trigger to update updated_at timestamp
	CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $$
	BEGIN
		NEW.updated_at = NOW();
		RETURN NEW;
	END;
	$$ language 'plpgsql';

	CREATE TRIGGER update_users_updated_at BEFORE UPDATE
		ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
	`

	_, err := us.db.Exec(query)
	return err
}

// CreateUser creates a new user account
func (us *UserService) CreateUser(req CreateUserRequest) (*User, error) {
	// Validate input
	if len(req.Username) < 3 || len(req.Username) > 255 {
		return nil, fmt.Errorf("username must be between 3 and 255 characters")
	}
	if len(req.Password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	if !strings.Contains(req.Email, "@") {
		return nil, fmt.Errorf("invalid email format")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	query := `
		INSERT INTO users (username, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`

	err = us.db.QueryRow(query, user.Username, user.Email, user.PasswordHash).Scan(
		&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				if strings.Contains(pqErr.Detail, "username") {
					return nil, fmt.Errorf("username already exists")
				}
				if strings.Contains(pqErr.Detail, "email") {
					return nil, fmt.Errorf("email already exists")
				}
			}
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Clear password hash before returning
	user.PasswordHash = ""
	return user, nil
}

// AuthenticateUser authenticates a user and returns a JWT token
func (us *UserService) AuthenticateUser(req LoginRequest, ipAddress, userAgent string) (*Session, error) {
	// Get user from database
	user, err := us.getUserByUsername(req.Username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if account is locked
	if user.AccountLocked {
		return nil, fmt.Errorf("account is locked")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// Increment failed login count
		us.incrementFailedLoginCount(user.ID)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check MFA if enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			return nil, fmt.Errorf("MFA code required")
		}

		valid := false
		
		// Check TOTP code
		if totp.Validate(req.MFACode, user.MFASecret) {
			valid = true
		} else {
			// Check backup codes
			for i, backupCode := range user.MFABackupCodes {
				if subtle.ConstantTimeCompare([]byte(req.MFACode), []byte(backupCode)) == 1 {
					valid = true
					// Remove used backup code
					user.MFABackupCodes = append(user.MFABackupCodes[:i], user.MFABackupCodes[i+1:]...)
					us.updateUserMFABackupCodes(user.ID, user.MFABackupCodes)
					break
				}
			}
		}

		if !valid {
			us.incrementFailedLoginCount(user.ID)
			return nil, fmt.Errorf("invalid MFA code")
		}
	}

	// Reset failed login count and update last login
	us.resetFailedLoginCount(user.ID)

	// Generate JWT token
	token, err := us.generateJWT(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Create session
	session := &Session{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	// Store session in database and Redis
	err = us.storeSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	return session, nil
}

// EnableMFA enables multi-factor authentication for a user
func (us *UserService) EnableMFA(userID string) (*EnableMFAResponse, error) {
	user, err := us.getUserByID(userID)
	if err != nil {
		return nil, err
	}

	if user.MFAEnabled {
		return nil, fmt.Errorf("MFA already enabled")
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      us.serviceName,
		AccountName: user.Email,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}