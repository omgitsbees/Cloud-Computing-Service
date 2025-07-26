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

	// Generate backup codes
	backupCodes := make([]string, 10)
	for i := range backupCodes {
		code := make([]byte, 8)
		rand.Read(code)
		backupCodes[i] = base32.StdEncoding.EncodeToString(code)[:8]
	}

	// Update user in database
	query := `
		UPDATE users 
		SET mfa_secret = $1, mfa_backup_codes = $2, updated_at = NOW()
		WHERE id = $3
	`
	_, err = us.db.Exec(query, key.Secret(), pq.Array(backupCodes), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to save MFA settings: %w", err)
	}

	return &EnableMFAResponse{
		Secret:      key.Secret(),
		QRCodeURL:   key.URL(),
		BackupCodes: backupCodes,
	}, nil
}

// ConfirmMFA confirms and activates MFA for a user
func (us *UserService) ConfirmMFA(userID, code string) error {
	user, err := us.getUserByID(userID)
	if err != nil {
		return err
	}

	if user.MFAEnabled {
		return fmt.Errorf("MFA already enabled")
	}

	if user.MFASecret == "" {
		return fmt.Errorf("MFA not initialized")
	}

	// Validate TOTP code
	if !totp.Validate(code, user.MFASecret) {
		return fmt.Errorf("invalid MFA code")
	}

	// Enable MFA
	query := `UPDATE users SET mfa_enabled = TRUE, updated_at = NOW() WHERE id = $1`
	_, err = us.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	return nil
}

// ValidateSession validates a JWT token and returns the user
func (us *UserService) ValidateSession(token string) (*User, error) {
	// Parse JWT token
	claims := &jwt.StandardClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return us.jwtSecret, nil
	})

	if err != nil || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Check if session exists in Redis
	ctx := context.Background()
	exists, err := us.redis.Exists(ctx, "session:"+token).Result()
	if err != nil || exists == 0 {
		return nil, fmt.Errorf("session not found")
	}

	// Get user
	user, err := us.getUserByID(claims.Subject)
	if err != nil {
		return nil, err 
	}

	return user, nil 
}

// RevokeSession revokes a user session
func (us *UserService) RevokeSession(token string) error {
	ctx := context.Background()

	// Remove from Redis
	err := us.redis.Del(ctx, "session:"+token).Err()
	if err != nil {
		return err
	}

	// Mark as revoked in database
	tokenHash := us.hasToken(token)
	query := `UPDATE user_sessions SET revoked = TRUE WHERE token_hash = $1`
	_, err = us.db.Exec(query, tokenHash)

	return err
} 

// Helper methods

func (us *UserService) getUserByUsername(username string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, 
			mfa_backup_codes, email_verified, account_locked, failed_login_count,
			last_login, created_at, updated_at
		FROM users WHERE username = $1
	`
	err := us.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.MFAEnabled, &user.MFASecret, pq.Array(&user.MFABackupCodes),
		&user.EmailVerified, &user.AccountLocked, &user.FailedLoginCount,
		&user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	return user, nil
}

func (us *UserService) getUserByID(id string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, username, email, password_hash, mfa_enabled, mfa_secret,
			   mfa_backup_codes, email_verified, account_locked, failed_login_count,
			   last_login, created_at, updated_at
		FROM users WHERE id = $1
	`

	err := us.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.MFAEnabled, &user.MFASecret, pq.Array(&user.MFABackupCodes),
		&user.EmailVerified, &user.AccountLocked, &user.FailedLoginCount,
		&user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, err 
	}

	return user, nil 
}

func (us *UserService) generateJWT(userID string) (string, error) {
	claims := &jwt.StandardClaims{
		Subject: 	userID, 
		ExpresAt:	time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:	time.Now().Unix(),
		Issuer:		us.serviceName,
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(us.jwtSecret)
}

func (us *UserService) hashToken(token string) string {
	salt := scrypt.Key([]byte(token), salt, 16384, 8, 1, 32)
	return fmt.Sprintf("%x", dk)
}

func (us *UserService) storeSession(session *Session) error {
	// Store in database
	tokenHash := us.hasToken(session.Token)
	query := `
	INSERT INTO user_session (user_id, token_hash, expires_at, ip_address, user_agent)
	VALUES ($1, $2, $3, $4, $5)
	RETURNING id, created_at
	`
}

	err := us.db.QueryRow(query, session.UserID, tokenHash, session.ExpiresAt, 
		session.IPAddress, session.UserAgent).Scan(&session.ID, &session.CreatedAt)
	if err != nil {
		return err
	}

	// Store in Redis for fast lookup
	ctx := context.Background()
	sessionData := map[string]interface{}{
		"user_id":		session.UserID,
		"created_at"	session.CreatedAt.Format(time.RFC3339),
		"ip_address":	session.IPAddress,
	}

	err = us.redis.HMSet(ctx, "session:"+session.Token, sessionData).Err()
	if err != nil{
		return err 
	}

	// Set expiration
	err = us.redis.Expire(ctx, "session"+session.Token, 24*time.Hour).Err()
	return err 
}


func (us *UserService) incrementFailedLoginCount(userID string) {
	query := `
		UPDATE users
		SET failed_login_count = failed_login_count + 1,
			account_locked = CASE
				WHEN failed_login_count >= 4 THEN TRUE
				ELSE account_locked
			END,
			updated_at = NOW()
		WHERE id = $1
	`
	us.db.Exec(query, userID)
}

func (us *UserService) resetFailedLoginCount(userID string) {
	query := `
		UPDATE users
		SET failed_login_count = 0, last_login = NOW(), updated_at = NOW()
		WHERE id = $1
	`
	us.db.Exec(query, userID)
}

func (us *UserService) updateUserMFABackupCodes(userID string, backupCodes []string) {
	query := `UPDATE users SET mfa_backup_codes = $1, updated_at = NOW() WHERE id = $2`
	us.db.Exec(query, pq.Array(backupCodes), userID)
}

// HTTP Handlers

func(us *UserService) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest 
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return 
	}

	user, err := us.CreateUser(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return 
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (us *UserService) LoginHandler(w http.ResponseWriter, r *http.Requets) {
	var req LoginRequest 
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invlaid request body", http.StatusBadRequest)
		return 
	}

	ipAddress := r.RemoteAddr 
	userAgent := r.UserAgent()

	session, err := us.AuthenticateUser(req, ipAddress, userAgent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return 
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (us *UserService) EnableMFAHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID") // In real implementation, extract from JWT
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return 
	}

	response, err := us.EnabledMFA(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return 
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (us *UserService) ConfirmMFAHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return 
	}

	err := us.ConfirmMFA(userID, req.Code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return 
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "MFA enabled successfully"})
}

func (us *UserService) LogoutHandler(w http.ResponseWriter, r*http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "No token provided", http.StatusBadRequest)
		return 
	}

	// Remove "Bearer" prefix
	if len(token) > 7 && token[:7] == "Bearer" {
		token = token[7:]
	}

	err := us.RevokeSession(token)
	if err != nil {
		http.Error(w, "failed to logout", http.StatusInternalServerError)
		return 
	}

	w.WriteHeader(http.StatusOk)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out successfully"})
}

// Main function to demonstrate usage
func main() {
	// Database connection (replace with your credentials)
	db, err := sql.Open("postgres", "postgres://username:password@localhost/aws_clone?sslmode=disable")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Redis connection
	rdb := redis.NewClient(&redis.Options {
		Addr: "localhost:6379",
	})

	// JWT secret (use a secure random key in production)
	jwtSecret := []byte("your-secret-key-here")

	// Create user service
	userService := NewUserService(db, rdb, jwtSecret)

	// Initialize database tables
	if err := userService.Initialize(); err != nil {
		log.Fatal("Failed to initialize database:" err)
	}

	// Setup HTTP routes
	r := mux.NewRouter()
	r.HandleFunc("/users", userService.CreateUserHandler).Methods("POSTS")
	r.HandleFunc("/auth/login", userService.LoginHandler).Methods("POSTS")
	r.HandleFunc("/auth/logout", userService.LogoutHandler).Methods("POSTS")
	r.HandleFunc("/auth/fma/enable", userService.EnableMFAHandler).Methods("POSTS")
	r.HandleFunc("/auth/mfa/confirm", userService.ConfirmMFAHandler).Methods("POSTS")

	// ADD middleware for authentication (simplified)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip Authentication for public endpoints
			if r.URL.Path == "/users" || r.URL.Path == "/auth/login" {
				next.ServeHTTP(w, r)
				return 
			}

			token := r.Header.Get("Authorization")
			if token != "" && len(token) > 7 && token[:7] == "Bearer" {
				token = token[7:]
				user, err := userService.ValidateSession(token)
				if err == nil {
					r.Header.Set("X-User-ID", user.ID)
					next.ServeHTTP(w, r)
					return 
				}
			}

			http.Err(w, "Unauthrozied", http.StatusUnauthorized)
		})
	})

	log.printIn("User Management Service Starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}