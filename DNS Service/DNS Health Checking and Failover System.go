package healthcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// HealthCheckType defines the type of health check
type HealthCheckType string

const (
	HealthCheckHTTP     HealthCheckType = "HTTP"
	HealthCheckHTTPS    HealthCheckType = "HTTPS"
	HealthCheckTCP      HealthCheckType = "TCP"
	HealthCheckPing     HealthCheckType = "PING"
	HealthCheckDNS      HealthCheckType = "DNS"
)

// HealthStatus represents the health status of an endpoint
type HealthStatus string

const (
	StatusHealthy   HealthStatus = "HEALTHY"
	StatusUnhealthy HealthStatus = "UNHEALTHY"
	StatusUnknown   HealthStatus = "UNKNOWN"
)

// HealthCheckConfig defines the configuration for a health check
type HealthCheckConfig struct {
	ID               string
	Type             HealthCheckType
	Target           string // IP address or domain name
	Port             int
	Path             string // For HTTP/HTTPS checks
	Interval         time.Duration
	Timeout          time.Duration
	FailureThreshold int // Number of consecutive failures before marking unhealthy
	SuccessThreshold int // Number of consecutive successes before marking healthy
	EnableSNI        bool
	ExpectedStatus   int    // For HTTP checks
	SearchString     string // Optional string to search in response
}

// HealthCheckResult represents the result of a single health check
type HealthCheckResult struct {
	CheckID    string
	Target     string
	Status     HealthStatus
	Latency    time.Duration
	Message    string
	Timestamp  time.Time
	StatusCode int // For HTTP checks
}

// EndpointHealth tracks the health state of an endpoint
type EndpointHealth struct {
	Config            *HealthCheckConfig
	CurrentStatus     HealthStatus
	ConsecutiveFails  int
	ConsecutivePass   int
	LastCheck         time.Time
	LastStatusChange  time.Time
	TotalChecks       int64
	FailedChecks      int64
	AverageLatency    time.Duration
	mu                sync.RWMutex
}

// HealthChecker manages health checks for multiple endpoints
type HealthChecker struct {
	endpoints map[string]*EndpointHealth
	mu        sync.RWMutex
	stopCh    chan struct{}
	wg        sync.WaitGroup
	callbacks []HealthChangeCallback
}

// HealthChangeCallback is called when an endpoint's health status changes
type HealthChangeCallback func(checkID string, oldStatus, newStatus HealthStatus)

// NewHealthChecker creates a new health checker instance
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		endpoints: make(map[string]*EndpointHealth),
		stopCh:    make(chan struct{}),
		callbacks: make([]HealthChangeCallback, 0),
	}
}

// AddHealthCheck registers a new health check
func (hc *HealthChecker) AddHealthCheck(config *HealthCheckConfig) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if _, exists := hc.endpoints[config.ID]; exists {
		return fmt.Errorf("health check %s already exists", config.ID)
	}

	endpoint := &EndpointHealth{
		Config:        config,
		CurrentStatus: StatusUnknown,
		LastCheck:     time.Now(),
	}

	hc.endpoints[config.ID] = endpoint

	// Start monitoring this endpoint
	hc.wg.Add(1)
	go hc.monitorEndpoint(endpoint)

	return nil
}

// RemoveHealthCheck removes a health check
func (hc *HealthChecker) RemoveHealthCheck(checkID string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if _, exists := hc.endpoints[checkID]; !exists {
		return fmt.Errorf("health check %s not found", checkID)
	}

	delete(hc.endpoints, checkID)
	return nil
}

// GetEndpointStatus returns the current status of an endpoint
func (hc *HealthChecker) GetEndpointStatus(checkID string) (HealthStatus, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	endpoint, exists := hc.endpoints[checkID]
	if !exists {
		return StatusUnknown, fmt.Errorf("health check %s not found", checkID)
	}

	endpoint.mu.RLock()
	defer endpoint.mu.RUnlock()
	return endpoint.CurrentStatus, nil
}

// GetEndpointHealth returns detailed health information
func (hc *HealthChecker) GetEndpointHealth(checkID string) (*EndpointHealth, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	endpoint, exists := hc.endpoints[checkID]
	if !exists {
		return nil, fmt.Errorf("health check %s not found", checkID)
	}

	return endpoint, nil
}

// RegisterCallback registers a callback for health status changes
func (hc *HealthChecker) RegisterCallback(callback HealthChangeCallback) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.callbacks = append(hc.callbacks, callback)
}

// monitorEndpoint continuously monitors an endpoint
func (hc *HealthChecker) monitorEndpoint(endpoint *EndpointHealth) {
	defer hc.wg.Done()

	ticker := time.NewTicker(endpoint.Config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopCh:
			return
		case <-ticker.C:
			result := hc.performHealthCheck(endpoint.Config)
			hc.updateEndpointHealth(endpoint, result)
		}
	}
}

// performHealthCheck executes a health check based on the configuration
func (hc *HealthChecker) performHealthCheck(config *HealthCheckConfig) *HealthCheckResult {
	result := &HealthCheckResult{
		CheckID:   config.ID,
		Target:    config.Target,
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	startTime := time.Now()

	switch config.Type {
	case HealthCheckHTTP, HealthCheckHTTPS:
		result = hc.checkHTTP(ctx, config)
	case HealthCheckTCP:
		result = hc.checkTCP(ctx, config)
	case HealthCheckPing:
		result = hc.checkPing(ctx, config)
	default:
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("unsupported health check type: %s", config.Type)
	}

	result.Latency = time.Since(startTime)
	return result
}

// checkHTTP performs an HTTP/HTTPS health check
func (hc *HealthChecker) checkHTTP(ctx context.Context, config *HealthCheckConfig) *HealthCheckResult {
	result := &HealthCheckResult{
		CheckID:   config.ID,
		Target:    config.Target,
		Timestamp: time.Now(),
	}

	scheme := "http"
	if config.Type == HealthCheckHTTPS {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, config.Target, config.Port, config.Path)

	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.EnableSNI,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check status code
	expectedStatus := config.ExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	if resp.StatusCode != expectedStatus {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("unexpected status code: %d (expected %d)", resp.StatusCode, expectedStatus)
		return result
	}

	// Check for search string if configured
	if config.SearchString != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			result.Status = StatusUnhealthy
			result.Message = fmt.Sprintf("failed to read response body: %v", err)
			return result
		}

		if !contains(string(body), config.SearchString) {
			result.Status = StatusUnhealthy
			result.Message = fmt.Sprintf("search string '%s' not found in response", config.SearchString)
			return result
		}
	}

	result.Status = StatusHealthy
	result.Message = "health check passed"
	return result
}

// checkTCP performs a TCP health check
func (hc *HealthChecker) checkTCP(ctx context.Context, config *HealthCheckConfig) *HealthCheckResult {
	result := &HealthCheckResult{
		CheckID:   config.ID,
		Target:    config.Target,
		Timestamp: time.Now(),
	}

	address := fmt.Sprintf("%s:%d", config.Target, config.Port)

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("TCP connection failed: %v", err)
		return result
	}
	defer conn.Close()

	result.Status = StatusHealthy
	result.Message = "TCP connection successful"
	return result
}

// checkPing performs an ICMP ping check
func (hc *HealthChecker) checkPing(ctx context.Context, config *HealthCheckConfig) *HealthCheckResult {
	result := &HealthCheckResult{
		CheckID:   config.ID,
		Target:    config.Target,
		Timestamp: time.Now(),
	}

	// Simple TCP-based connectivity check as ICMP requires privileges
	// In production, use a proper ICMP library
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "ip4:icmp", config.Target)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("ping failed: %v", err)
		return result
	}
	defer conn.Close()

	result.Status = StatusHealthy
	result.Message = "ping successful"
	return result
}

// updateEndpointHealth updates the health status based on check results
func (hc *HealthChecker) updateEndpointHealth(endpoint *EndpointHealth, result *HealthCheckResult) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()

	oldStatus := endpoint.CurrentStatus
	endpoint.LastCheck = result.Timestamp
	endpoint.TotalChecks++

	if result.Status == StatusHealthy {
		endpoint.ConsecutivePass++
		endpoint.ConsecutiveFails = 0

		// Check if we should mark as healthy
		if endpoint.ConsecutivePass >= endpoint.Config.SuccessThreshold {
			if endpoint.CurrentStatus != StatusHealthy {
				endpoint.CurrentStatus = StatusHealthy
				endpoint.LastStatusChange = time.Now()
				hc.notifyStatusChange(endpoint.Config.ID, oldStatus, StatusHealthy)
			}
		}
	} else {
		endpoint.ConsecutiveFails++
		endpoint.ConsecutivePass = 0
		endpoint.FailedChecks++

		// Check if we should mark as unhealthy
		if endpoint.ConsecutiveFails >= endpoint.Config.FailureThreshold {
			if endpoint.CurrentStatus != StatusUnhealthy {
				endpoint.CurrentStatus = StatusUnhealthy
				endpoint.LastStatusChange = time.Now()
				hc.notifyStatusChange(endpoint.Config.ID, oldStatus, StatusUnhealthy)
			}
		}
	}

	// Update average latency
	if endpoint.TotalChecks == 1 {
		endpoint.AverageLatency = result.Latency
	} else {
		endpoint.AverageLatency = time.Duration(
			(int64(endpoint.AverageLatency)*int64(endpoint.TotalChecks-1) + int64(result.Latency)) / int64(endpoint.TotalChecks),
		)
	}
}

// notifyStatusChange calls all registered callbacks
func (hc *HealthChecker) notifyStatusChange(checkID string, oldStatus, newStatus HealthStatus) {
	hc.mu.RLock()
	callbacks := make([]HealthChangeCallback, len(hc.callbacks))
	copy(callbacks, hc.callbacks)
	hc.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(checkID, oldStatus, newStatus)
	}
}

// Stop stops all health checks
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
	hc.wg.Wait()
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}