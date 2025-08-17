// Certificate Management Service
package certmanager

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/redis/go-redis/v9"
    "gorm.io/gorm"
)

// ServiceCertificate represents a service's TLS certificate
type ServiceCertificate struct {
    ID          uint      `gorm:"primaryKey"`
    ServiceID   string    `gorm:"uniqueIndex;not null"`
    ServiceName string    `gorm:"not null"`
    CertPEM     string    `gorm:"type:text;not null"`
    KeyPEM      string    `gorm:"type:text;not null"`
    SerialNum   string    `gorm:"not null"`
    IssuedAt    time.Time `gorm:"not null"`
    ExpiresAt   time.Time `gorm:"not null"`
    Revoked     bool      `gorm:"default:false"`
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

// CertManager handles certificate lifecycle
type CertManager struct {
    db          *gorm.DB
    redis       *redis.Client
    caCert      *x509.Certificate
    caKey       *rsa.PrivateKey
    certCache   sync.Map
    mu          sync.RWMutex
}

// NewCertManager creates a new certificate manager
func NewCertManager(db *gorm.DB, redis *redis.Client, caCertPEM, caKeyPEM []byte) (*CertManager, error) {
    // Parse CA certificate
    caCertBlock, _ := pem.Decode(caCertPEM)
    if caCertBlock == nil {
        return nil, fmt.Errorf("failed to decode CA certificate")
    }
    caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
    }

    // Parse CA private key
    caKeyBlock, _ := pem.Decode(caKeyPEM)
    if caKeyBlock == nil {
        return nil, fmt.Errorf("failed to decode CA private key")
    }
    caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse CA private key: %w", err)
    }

    cm := &CertManager{
        db:     db,
        redis:  redis,
        caCert: caCert,
        caKey:  caKey,
    }

    // Auto-migrate database
    if err := db.AutoMigrate(&ServiceCertificate{}); err != nil {
        return nil, fmt.Errorf("failed to migrate database: %w", err)
    }

    return cm, nil
}

// IssueServiceCertificate issues a new certificate for a service
func (cm *CertManager) IssueServiceCertificate(serviceID, serviceName string) (*ServiceCertificate, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    // Generate private key for service
    serviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, fmt.Errorf("failed to generate service private key: %w", err)
    }

    // Create certificate template
    serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %w", err)
    }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization:       []string{"CloudPlatform"},
            OrganizationalUnit: []string{"Services"},
            CommonName:         serviceName,
        },
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(30 * 24 * time.Hour), // 30 days
        KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        IPAddresses:  nil, // Will be populated by service discovery
        DNSNames:     []string{serviceName, fmt.Sprintf("%s.internal", serviceName)},
    }

    // Create certificate
    certDER, err := x509.CreateCertificate(rand.Reader, &template, cm.caCert, &serviceKey.PublicKey, cm.caKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create certificate: %w", err)
    }

    // Encode certificate and key to PEM
    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serviceKey)})

    // Save to database
    serviceCert := &ServiceCertificate{
        ServiceID:   serviceID,
        ServiceName: serviceName,
        CertPEM:     string(certPEM),
        KeyPEM:      string(keyPEM),
        SerialNum:   serialNumber.String(),
        IssuedAt:    template.NotBefore,
        ExpiresAt:   template.NotAfter,
    }

    if err := cm.db.Create(serviceCert).Error; err != nil {
        return nil, fmt.Errorf("failed to save certificate: %w", err)
    }

    // Cache certificate
    cm.certCache.Store(serviceID, serviceCert)

    return serviceCert, nil
}

// GetServiceCertificate retrieves a service's certificate
func (cm *CertManager) GetServiceCertificate(serviceID string) (*ServiceCertificate, error) {
    // Check cache first
    if cached, ok := cm.certCache.Load(serviceID); ok {
        cert := cached.(*ServiceCertificate)
        if time.Now().Before(cert.ExpiresAt) && !cert.Revoked {
            return cert, nil
        }
        cm.certCache.Delete(serviceID)
    }

    // Load from database
    var cert ServiceCertificate
    if err := cm.db.Where("service_id = ? AND revoked = false", serviceID).First(&cert).Error; err != nil {
        return nil, fmt.Errorf("certificate not found: %w", err)
    }

    // Check if expired
    if time.Now().After(cert.ExpiresAt) {
        return nil, fmt.Errorf("certificate expired")
    }

    // Cache and return
    cm.certCache.Store(serviceID, &cert)
    return &cert, nil
}

// Request Signing System
package signing

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "sort"
    "strconv"
    "strings"
    "time"
)

// SigningCredentials contains service credentials for request signing
type SigningCredentials struct {
    AccessKeyID     string
    SecretAccessKey string
    ServiceID       string
}

// RequestSigner handles request signing and verification
type RequestSigner struct {
    algorithm string
}

// NewRequestSigner creates a new request signer
func NewRequestSigner() *RequestSigner {
    return &RequestSigner{
        algorithm: "CLOUDPLATFORM-HMAC-SHA256",
    }
}

// SignRequest signs an HTTP request with service credentials
func (rs *RequestSigner) SignRequest(req *http.Request, creds *SigningCredentials, body []byte) error {
    if req == nil || creds == nil {
        return fmt.Errorf("request and credentials cannot be nil")
    }

    timestamp := time.Now().UTC().Format("20060102T150405Z")
    date := timestamp[:8]

    // Set required headers
    req.Header.Set("X-CloudPlatform-Date", timestamp)
    req.Header.Set("X-CloudPlatform-Service-ID", creds.ServiceID)
    req.Header.Set("Host", req.Host)

    // Create canonical request
    canonicalReq := rs.createCanonicalRequest(req, body)
    
    // Create string to sign
    credentialScope := fmt.Sprintf("%s/cloudplatform/request", date)
    stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
        rs.algorithm,
        timestamp,
        credentialScope,
        rs.hash(canonicalReq))

    // Calculate signature
    signingKey := rs.getSigningKey(creds.SecretAccessKey, date)
    signature := rs.hmacSHA256(signingKey, stringToSign)

    // Create authorization header
    authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
        rs.algorithm,
        creds.AccessKeyID,
        credentialScope,
        rs.getSignedHeaders(req),
        hex.EncodeToString(signature))

    req.Header.Set("Authorization", authHeader)
    return nil
}

// VerifyRequest verifies a signed request
func (rs *RequestSigner) VerifyRequest(req *http.Request, body []byte, getCredentials func(accessKeyID string) (*SigningCredentials, error)) error {
    authHeader := req.Header.Get("Authorization")
    if authHeader == "" {
        return fmt.Errorf("missing authorization header")
    }

    // Parse authorization header
    parts := strings.Fields(authHeader)
    if len(parts) != 4 || parts[0] != rs.algorithm {
        return fmt.Errorf("invalid authorization header format")
    }

    var accessKeyID, credentialScope, signedHeaders, providedSignature string
    for _, part := range parts[1:] {
        kv := strings.SplitN(part, "=", 2)
        if len(kv) != 2 {
            continue
        }
        switch kv[0] {
        case "Credential":
            credParts := strings.SplitN(kv[1], "/", 2)
            if len(credParts) == 2 {
                accessKeyID = credParts[0]
                credentialScope = credParts[1]
            }
        case "SignedHeaders":
            signedHeaders = kv[1]
        case "Signature":
            providedSignature = strings.TrimSuffix(kv[1], ",")
        }
    }

    if accessKeyID == "" || providedSignature == "" {
        return fmt.Errorf("invalid authorization header")
    }

    // Get credentials
    creds, err := getCredentials(accessKeyID)
    if err != nil {
        return fmt.Errorf("invalid credentials: %w", err)
    }

    // Verify timestamp (prevent replay attacks)
    timestamp := req.Header.Get("X-CloudPlatform-Date")
    if timestamp == "" {
        return fmt.Errorf("missing timestamp header")
    }

    reqTime, err := time.Parse("20060102T150405Z", timestamp)
    if err != nil {
        return fmt.Errorf("invalid timestamp format: %w", err)
    }

    if time.Since(reqTime) > 15*time.Minute {
        return fmt.Errorf("request timestamp too old")
    }

    // Recreate signature
    canonicalReq := rs.createCanonicalRequest(req, body)
    stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
        rs.algorithm,
        timestamp,
        credentialScope,
        rs.hash(canonicalReq))

    date := timestamp[:8]
    signingKey := rs.getSigningKey(creds.SecretAccessKey, date)
    expectedSignature := hex.EncodeToString(rs.hmacSHA256(signingKey, stringToSign))

    if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
        return fmt.Errorf("signature verification failed")
    }

    return nil
}

// createCanonicalRequest creates a canonical representation of the request
func (rs *RequestSigner) createCanonicalRequest(req *http.Request, body []byte) string {
    method := req.Method
    path := req.URL.Path
    if path == "" {
        path = "/"
    }

    // Canonical query string
    query := req.URL.Query()
    var queryParts []string
    for k, vs := range query {
        for _, v := range vs {
            queryParts = append(queryParts, fmt.Sprintf("%s=%s", k, v))
        }
    }
    sort.Strings(queryParts)
    canonicalQuery := strings.Join(queryParts, "&")

    // Canonical headers
    var headerParts []string
    signedHeaders := rs.getSignedHeadersList(req)
    for _, h := range signedHeaders {
        value := strings.Join(req.Header.Values(h), ",")
        headerParts = append(headerParts, fmt.Sprintf("%s:%s", strings.ToLower(h), strings.TrimSpace(value)))
    }
    canonicalHeaders := strings.Join(headerParts, "\n") + "\n"

    // Payload hash
    payloadHash := rs.hash(string(body))

    return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
        method,
        path,
        canonicalQuery,
        canonicalHeaders,
        rs.getSignedHeaders(req),
        payloadHash)
}

// getSignedHeaders returns the signed headers string
func (rs *RequestSigner) getSignedHeaders(req *http.Request) string {
    headers := rs.getSignedHeadersList(req)
    return strings.Join(headers, ";")
}

// getSignedHeadersList returns the list of headers to sign
func (rs *RequestSigner) getSignedHeadersList(req *http.Request) []string {
    var headers []string
    for name := range req.Header {
        lowerName := strings.ToLower(name)
        if lowerName == "host" || strings.HasPrefix(lowerName, "x-cloudplatform-") {
            headers = append(headers, lowerName)
        }
    }
    sort.Strings(headers)
    return headers
}

// getSigningKey derives the signing key
func (rs *RequestSigner) getSigningKey(secretKey, date string) []byte {
    kDate := rs.hmacSHA256([]byte("CLOUDPLATFORM"+secretKey), date)
    kService := rs.hmacSHA256(kDate, "cloudplatform")
    kSigning := rs.hmacSHA256(kService, "request")
    return kSigning
}

// hmacSHA256 computes HMAC-SHA256
func (rs *RequestSigner) hmacSHA256(key []byte, data string) []byte {
    h := hmac.New(sha256.New, key)
    h.Write([]byte(data))
    return h.Sum(nil)
}

// hash computes SHA256 hash
func (rs *RequestSigner) hash(data string) string {
    h := sha256.New()
    h.Write([]byte(data))
    return hex.EncodeToString(h.Sum(nil))
}

// Service Authentication Middleware
package middleware

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
)

// ServicePrincipal represents an authenticated service
type ServicePrincipal struct {
    ServiceID   string
    ServiceName string
    AccessKeyID string
    Permissions []string
}

// AuthMiddleware handles service authentication
type AuthMiddleware struct {
    db          *gorm.DB
    signer      *RequestSigner
    certManager *CertManager
    policyEng   PolicyEngine
}

// PolicyEngine interface for authorization decisions
type PolicyEngine interface {
    CheckPermission(serviceID, resource, action string) error
    GetServicePermissions(serviceID string) ([]string, error)
}

// ServiceCredentials represents stored service credentials
type ServiceCredentials struct {
    ID              uint   `gorm:"primaryKey"`
    ServiceID       string `gorm:"uniqueIndex;not null"`
    AccessKeyID     string `gorm:"uniqueIndex;not null"`
    SecretAccessKey string `gorm:"not null"` // Encrypted
    Active          bool   `gorm:"default:true"`
    CreatedAt       time.Time
    UpdatedAt       time.Time
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(db *gorm.DB, signer *RequestSigner, certManager *CertManager, policyEng PolicyEngine) *AuthMiddleware {
    am := &AuthMiddleware{
        db:          db,
        signer:      signer,
        certManager: certManager,
        policyEng:   policyEng,
    }

    // Auto-migrate
    db.AutoMigrate(&ServiceCredentials{})
    return am
}

// MTLSMiddleware validates mTLS certificates
func (am *AuthMiddleware) MTLSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get client certificate from TLS connection
        if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
            c.JSON(401, gin.H{"error": "client certificate required"})
            c.Abort()
            return
        }

        clientCert := c.Request.TLS.PeerCertificates[0]
        
        // Verify certificate is issued by our CA
        // This would typically be done by the TLS layer, but we add extra validation
        if !am.isValidServiceCertificate(clientCert) {
            c.JSON(401, gin.H{"error": "invalid service certificate"})
            c.Abort()
            return
        }

        // Extract service information from certificate
        serviceID := am.extractServiceIDFromCert(clientCert)
        if serviceID == "" {
            c.JSON(401, gin.H{"error": "cannot identify service from certificate"})
            c.Abort()
            return
        }

        // Store service info in context for signature verification
        c.Set("mtls_service_id", serviceID)
        c.Next()
    }
}

// SignatureMiddleware validates request signatures
func (am *AuthMiddleware) SignatureMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Read request body for signature verification
        body, err := io.ReadAll(c.Request.Body)
        if err != nil {
            c.JSON(400, gin.H{"error": "failed to read request body"})
            c.Abort()
            return
        }

        // Reset body for downstream handlers
        c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

        // Verify request signature
        err = am.signer.VerifyRequest(c.Request, body, am.getCredentials)
        if err != nil {
            c.JSON(401, gin.H{"error": fmt.Sprintf("signature verification failed: %v", err)})
            c.Abort()
            return
        }

        // Extract service principal from verified request
        serviceID := c.Request.Header.Get("X-CloudPlatform-Service-ID")
        principal, err := am.getServicePrincipal(serviceID)
        if err != nil {
            c.JSON(401, gin.H{"error": "invalid service principal"})
            c.Abort()
            return
        }

        // Verify mTLS and signature service IDs match
        if mtlsServiceID, exists := c.Get("mtls_service_id"); exists {
            if mtlsServiceID != serviceID {
                c.JSON(401, gin.H{"error": "service ID mismatch between mTLS and signature"})
                c.Abort()
                return
            }
        }

        // Store authenticated principal in context
        c.Set("service_principal", principal)
        c.Next()
    }
}

// AuthorizeMiddleware handles authorization
func (am *AuthMiddleware) AuthorizeMiddleware(resource, action string) gin.HandlerFunc {
    return func(c *gin.Context) {
        principal, exists := c.Get("service_principal")
        if !exists {
            c.JSON(401, gin.H{"error": "not authenticated"})
            c.Abort()
            return
        }

        servicePrincipal := principal.(*ServicePrincipal)

        // Check permission using policy engine
        err := am.policyEng.CheckPermission(servicePrincipal.ServiceID, resource, action)
        if err != nil {
            c.JSON(403, gin.H{"error": fmt.Sprintf("access denied: %v", err)})
            c.Abort()
            return
        }

        c.Next()
    }
}

// getCredentials retrieves service credentials for signature verification
func (am *AuthMiddleware) getCredentials(accessKeyID string) (*SigningCredentials, error) {
    var creds ServiceCredentials
    err := am.db.Where("access_key_id = ? AND active = true", accessKeyID).First(&creds).Error
    if err != nil {
        return nil, fmt.Errorf("credentials not found")
    }

    // Decrypt secret access key (implement proper decryption)
    secretKey := am.decryptSecretKey(creds.SecretAccessKey)

    return &SigningCredentials{
        AccessKeyID:     creds.AccessKeyID,
        SecretAccessKey: secretKey,
        ServiceID:       creds.ServiceID,
    }, nil
}

// getServicePrincipal creates a service principal
func (am *AuthMiddleware) getServicePrincipal(serviceID string) (*ServicePrincipal, error) {
    var creds ServiceCredentials
    err := am.db.Where("service_id = ? AND active = true", serviceID).First(&creds).Error
    if err != nil {
        return nil, fmt.Errorf("service not found")
    }

    permissions, err := am.policyEng.GetServicePermissions(serviceID)
    if err != nil {
        return nil, fmt.Errorf("failed to get permissions: %w", err)
    }

    return &ServicePrincipal{
        ServiceID:   serviceID,
        ServiceName: serviceID, // You might want to store service names separately
        AccessKeyID: creds.AccessKeyID,
        Permissions: permissions,
    }, nil
}

// Helper methods (implement based on your specific requirements)
func (am *AuthMiddleware) isValidServiceCertificate(cert *tls.Certificate) bool {
    // Implement certificate validation logic
    return true
}

func (am *AuthMiddleware) extractServiceIDFromCert(cert *tls.Certificate) string {
    // Extract service ID from certificate subject or extensions
    return "service-example"
}

func (am *AuthMiddleware) decryptSecretKey(encrypted string) string {
    // Implement proper key decryption
    return encrypted
}

// Service Client Library
package client

import (
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

// ServiceClient handles authenticated requests to other services
type ServiceClient struct {
    httpClient  *http.Client
    credentials *SigningCredentials
    signer      *RequestSigner
    baseURL     string
}

// ServiceClientConfig configuration for service client
type ServiceClientConfig struct {
    ServiceID       string
    AccessKeyID     string
    SecretAccessKey string
    ClientCertPath  string
    ClientKeyPath   string
    CACertPath      string
    BaseURL         string
    Timeout         time.Duration
}

// NewServiceClient creates a new authenticated service client
func NewServiceClient(config *ServiceClientConfig) (*ServiceClient, error) {
    // Load client certificate
    clientCert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load client certificate: %w", err)
    }

    // Load CA certificate
    caCert, err := os.ReadFile(config.CACertPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load CA certificate: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to parse CA certificate")
    }

    // Configure TLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }

    // Create HTTP client with mTLS
    timeout := config.Timeout
    if timeout == 0 {
        timeout = 30 * time.Second
    }

    httpClient := &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    credentials := &SigningCredentials{
        AccessKeyID:     config.AccessKeyID,
        SecretAccessKey: config.SecretAccessKey,
        ServiceID:       config.ServiceID,
    }

    return &ServiceClient{
        httpClient:  httpClient,
        credentials: credentials,
        signer:      NewRequestSigner(),
        baseURL:     config.BaseURL,
    }, nil
}

// Request makes an authenticated request to another service
func (sc *ServiceClient) Request(ctx context.Context, method, path string, body interface{}, result interface{}) error {
    // Prepare request body
    var reqBody []byte
    var err error
    if body != nil {
        reqBody, err = json.Marshal(body)
        if err != nil {
            return fmt.Errorf("failed to marshal request body: %w", err)
        }
    }

    // Create HTTP request
    url := sc.baseURL + path
    req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err