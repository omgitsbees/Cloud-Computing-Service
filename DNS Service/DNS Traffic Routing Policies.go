package dns

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// RoutingPolicy defines the routing strategy for DNS queries
type RoutingPolicy string

const (
	PolicySimple           RoutingPolicy = "simple"
	PolicyWeighted         RoutingPolicy = "weighted"
	PolicyLatency          RoutingPolicy = "latency"
	PolicyFailover         RoutingPolicy = "failover"
	PolicyGeolocation      RoutingPolicy = "geolocation"
	PolicyGeoproximity     RoutingPolicy = "geoproximity"
	PolicyMultiValue       RoutingPolicy = "multivalue"
	PolicyIPBased          RoutingPolicy = "ipbased"
)

// RoutingRecord represents a DNS record with routing policies
type RoutingRecord struct {
	ID             string
	Name           string
	Type           string
	TTL            uint32
	RoutingPolicy  RoutingPolicy
	Records        []RecordSet
	HealthCheckID  string
	SetIdentifier  string // Unique identifier for this routing policy record
}

// RecordSet represents a set of DNS records with routing metadata
type RecordSet struct {
	Values           []string
	Weight           int64              // For weighted routing
	Region           string             // For latency-based routing
	Priority         int                // For failover routing (lower = higher priority)
	HealthCheckID    string
	GeoLocation      *GeoLocation       // For geolocation routing
	Coordinates      *Coordinates       // For geoproximity routing
	Bias             int                // Geoproximity bias (-99 to 99)
	IPRanges         []string           // For IP-based routing
	SetIdentifier    string
	Healthy          bool
	LatencyMS        int64              // Measured latency for latency-based routing
}

// GeoLocation represents geographic location
type GeoLocation struct {
	ContinentCode   string
	CountryCode     string
	SubdivisionCode string // State/Province
}

// Coordinates represents geographic coordinates
type Coordinates struct {
	Latitude  float64
	Longitude float64
}

// RoutingPolicyEngine handles traffic routing decisions
type RoutingPolicyEngine struct {
	healthChecker  HealthChecker
	geoIPResolver  GeoIPResolver
	latencyTable   *LatencyTable
	mu             sync.RWMutex
}

// HealthChecker interface for health check integration
type HealthChecker interface {
	IsHealthy(ctx context.Context, healthCheckID string) bool
}

// GeoIPResolver interface for geographic IP resolution
type GeoIPResolver interface {
	GetLocation(ip net.IP) (*GeoLocation, error)
	GetCoordinates(ip net.IP) (*Coordinates, error)
}

// LatencyTable stores latency measurements between regions
type LatencyTable struct {
	measurements map[string]map[string]int64 // [sourceRegion][targetRegion]latency
	mu           sync.RWMutex
}

// NewRoutingPolicyEngine creates a new routing policy engine
func NewRoutingPolicyEngine(healthChecker HealthChecker, geoIPResolver GeoIPResolver) *RoutingPolicyEngine {
	return &RoutingPolicyEngine{
		healthChecker: healthChecker,
		geoIPResolver: geoIPResolver,
		latencyTable:  NewLatencyTable(),
	}
}

// NewLatencyTable creates a new latency table
func NewLatencyTable() *LatencyTable {
	return &LatencyTable{
		measurements: make(map[string]map[string]int64),
	}
}

// UpdateLatency updates latency measurement between regions
func (lt *LatencyTable) UpdateLatency(sourceRegion, targetRegion string, latencyMS int64) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	
	if lt.measurements[sourceRegion] == nil {
		lt.measurements[sourceRegion] = make(map[string]int64)
	}
	lt.measurements[sourceRegion][targetRegion] = latencyMS
}

// GetLatency retrieves latency between regions
func (lt *LatencyTable) GetLatency(sourceRegion, targetRegion string) int64 {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	
	if regions, ok := lt.measurements[sourceRegion]; ok {
		if latency, ok := regions[targetRegion]; ok {
			return latency
		}
	}
	return 0
}

// RouteQuery routes a DNS query based on the configured policy
func (e *RoutingPolicyEngine) RouteQuery(ctx context.Context, record *RoutingRecord, clientIP net.IP) ([]string, error) {
	// Filter healthy records
	healthyRecords := e.filterHealthyRecords(ctx, record.Records)
	
	if len(healthyRecords) == 0 {
		return nil, fmt.Errorf("no healthy records available")
	}
	
	switch record.RoutingPolicy {
	case PolicySimple:
		return e.routeSimple(healthyRecords)
	case PolicyWeighted:
		return e.routeWeighted(healthyRecords)
	case PolicyLatency:
		return e.routeLatency(healthyRecords, clientIP)
	case PolicyFailover:
		return e.routeFailover(healthyRecords)
	case PolicyGeolocation:
		return e.routeGeolocation(healthyRecords, clientIP)
	case PolicyGeoproximity:
		return e.routeGeoproximity(healthyRecords, clientIP)
	case PolicyMultiValue:
		return e.routeMultiValue(healthyRecords)
	case PolicyIPBased:
		return e.routeIPBased(healthyRecords, clientIP)
	default:
		return e.routeSimple(healthyRecords)
	}
}

// filterHealthyRecords filters records based on health checks
func (e *RoutingPolicyEngine) filterHealthyRecords(ctx context.Context, records []RecordSet) []RecordSet {
	healthy := make([]RecordSet, 0, len(records))
	
	for _, record := range records {
		if record.HealthCheckID != "" {
			if e.healthChecker != nil && e.healthChecker.IsHealthy(ctx, record.HealthCheckID) {
				record.Healthy = true
				healthy = append(healthy, record)
			}
		} else {
			// No health check configured, assume healthy
			record.Healthy = true
			healthy = append(healthy, record)
		}
	}
	
	return healthy
}

// routeSimple returns all values from the first record (round-robin handled by DNS resolver)
func (e *RoutingPolicyEngine) routeSimple(records []RecordSet) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	return records[0].Values, nil
}

// routeWeighted performs weighted random selection
func (e *RoutingPolicyEngine) routeWeighted(records []RecordSet) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	// Calculate total weight
	var totalWeight int64
	for _, record := range records {
		totalWeight += record.Weight
	}
	
	if totalWeight == 0 {
		// Equal weights, pick random
		idx := rand.Intn(len(records))
		return records[idx].Values, nil
	}
	
	// Weighted random selection
	randWeight := rand.Int63n(totalWeight)
	var cumulative int64
	
	for _, record := range records {
		cumulative += record.Weight
		if randWeight < cumulative {
			return record.Values, nil
		}
	}
	
	// Fallback (shouldn't reach here)
	return records[0].Values, nil
}

// routeLatency selects the record with lowest latency to client
func (e *RoutingPolicyEngine) routeLatency(records []RecordSet, clientIP net.IP) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	// Try to determine client's region
	clientRegion := "default"
	if e.geoIPResolver != nil {
		if loc, err := e.geoIPResolver.GetLocation(clientIP); err == nil && loc != nil {
			clientRegion = loc.CountryCode
		}
	}
	
	// Find record with lowest latency
	var bestRecord *RecordSet
	var lowestLatency int64 = -1
	
	for i := range records {
		record := &records[i]
		latency := e.latencyTable.GetLatency(clientRegion, record.Region)
		
		// Use configured latency if available, otherwise use measured
		if record.LatencyMS > 0 {
			latency = record.LatencyMS
		}
		
		if lowestLatency == -1 || latency < lowestLatency {
			lowestLatency = latency
			bestRecord = record
		}
	}
	
	if bestRecord != nil {
		return bestRecord.Values, nil
	}
	
	return records[0].Values, nil
}

// routeFailover returns primary record or fails over to secondary
func (e *RoutingPolicyEngine) routeFailover(records []RecordSet) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	// Sort by priority (lower number = higher priority)
	sorted := make([]RecordSet, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	
	// Return the highest priority healthy record
	for _, record := range sorted {
		if record.Healthy {
			return record.Values, nil
		}
	}
	
	return nil, fmt.Errorf("no healthy failover records available")
}

// routeGeolocation routes based on client's geographic location
func (e *RoutingPolicyEngine) routeGeolocation(records []RecordSet, clientIP net.IP) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	if e.geoIPResolver == nil {
		return records[0].Values, nil
	}
	
	clientLoc, err := e.geoIPResolver.GetLocation(clientIP)
	if err != nil {
		// Fallback to default location
		for _, record := range records {
			if record.GeoLocation == nil {
				return record.Values, nil
			}
		}
		return records[0].Values, nil
	}
	
	// Try to match: subdivision > country > continent > default
	// First try exact subdivision match
	for _, record := range records {
		if record.GeoLocation != nil &&
			record.GeoLocation.SubdivisionCode != "" &&
			record.GeoLocation.SubdivisionCode == clientLoc.SubdivisionCode {
			return record.Values, nil
		}
	}
	
	// Try country match
	for _, record := range records {
		if record.GeoLocation != nil &&
			record.GeoLocation.CountryCode != "" &&
			record.GeoLocation.CountryCode == clientLoc.CountryCode {
			return record.Values, nil
		}
	}
	
	// Try continent match
	for _, record := range records {
		if record.GeoLocation != nil &&
			record.GeoLocation.ContinentCode != "" &&
			record.GeoLocation.ContinentCode == clientLoc.ContinentCode {
			return record.Values, nil
		}
	}
	
	// Return default (record with no geolocation specified)
	for _, record := range records {
		if record.GeoLocation == nil {
			return record.Values, nil
		}
	}
	
	return records[0].Values, nil
}

// routeGeoproximity routes based on geographic proximity with bias
func (e *RoutingPolicyEngine) routeGeoproximity(records []RecordSet, clientIP net.IP) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	if e.geoIPResolver == nil {
		return records[0].Values, nil
	}
	
	clientCoords, err := e.geoIPResolver.GetCoordinates(clientIP)
	if err != nil {
		return records[0].Values, nil
	}
	
	// Calculate distance to each record with bias applied
	type scoredRecord struct {
		record   *RecordSet
		distance float64
	}
	
	scored := make([]scoredRecord, 0, len(records))
	
	for i := range records {
		record := &records[i]
		if record.Coordinates == nil {
			continue
		}
		
		distance := haversineDistance(
			clientCoords.Latitude, clientCoords.Longitude,
			record.Coordinates.Latitude, record.Coordinates.Longitude,
		)
		
		// Apply bias (negative bias reduces effective distance, positive increases it)
		// Each bias point = ~50km
		biasAdjustment := float64(record.Bias) * 50.0
		adjustedDistance := distance + biasAdjustment
		
		if adjustedDistance < 0 {
			adjustedDistance = 0
		}
		
		scored = append(scored, scoredRecord{
			record:   record,
			distance: adjustedDistance,
		})
	}
	
	if len(scored) == 0 {
		return records[0].Values, nil
	}
	
	// Sort by distance
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].distance < scored[j].distance
	})
	
	return scored[0].record.Values, nil
}

// routeMultiValue returns multiple random healthy values
func (e *RoutingPolicyEngine) routeMultiValue(records []RecordSet) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	// Collect all values from healthy records
	allValues := make([]string, 0)
	for _, record := range records {
		if record.Healthy {
			allValues = append(allValues, record.Values...)
		}
	}
	
	if len(allValues) == 0 {
		return nil, fmt.Errorf("no healthy values available")
	}
	
	// Return up to 8 random values (AWS Route 53 limit)
	maxValues := 8
	if len(allValues) <= maxValues {
		return allValues, nil
	}
	
	// Shuffle and return first 8
	rand.Shuffle(len(allValues), func(i, j int) {
		allValues[i], allValues[j] = allValues[j], allValues[i]
	})
	
	return allValues[:maxValues], nil
}

// routeIPBased routes based on client IP address ranges
func (e *RoutingPolicyEngine) routeIPBased(records []RecordSet, clientIP net.IP) ([]string, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records available")
	}
	
	// Try to find a matching IP range
	for _, record := range records {
		for _, ipRange := range record.IPRanges {
			_, network, err := net.ParseCIDR(ipRange)
			if err != nil {
				continue
			}
			
			if network.Contains(clientIP) {
				return record.Values, nil
			}
		}
	}
	
	// No match found, return default (first record with no IP ranges)
	for _, record := range records {
		if len(record.IPRanges) == 0 {
			return record.Values, nil
		}
	}
	
	return records[0].Values, nil
}

// haversineDistance calculates distance between two coordinates in kilometers
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371.0 // Earth's radius in kilometers
	
	// Convert to radians
	lat1Rad := lat1 * (3.14159265359 / 180.0)
	lon1Rad := lon1 * (3.14159265359 / 180.0)
	lat2Rad := lat2 * (3.14159265359 / 180.0)
	lon2Rad := lon2 * (3.14159265359 / 180.0)
	
	// Haversine formula
	dLat := lat2Rad - lat1Rad
	dLon := lon2Rad - lon1Rad
	
	a := (1 - cosApprox(dLat)) / 2 +
		cosApprox(lat1Rad) * cosApprox(lat2Rad) * (1 - cosApprox(dLon)) / 2
	
	c := 2 * asinApprox(sqrtApprox(a))
	
	return earthRadius * c
}

// Simple approximations for trigonometric functions
func cosApprox(x float64) float64 {
	// Taylor series approximation
	x2 := x * x
	return 1 - x2/2 + x2*x2/24
}

func sinApprox(x float64) float64 {
	x2 := x * x
	return x - x*x2/6 + x*x2*x2/120
}

func asinApprox(x float64) float64 {
	return x + x*x*x/6 + 3*x*x*x*x*x/40
}

func sqrtApprox(x float64) float64 {
	if x == 0 {
		return 0
	}
	// Newton's method
	guess := x / 2
	for i := 0; i < 10; i++ {
		guess = (guess + x/guess) / 2
	}
	return guess
}

// ShuffleRecordsConsistently provides consistent shuffling based on client IP
// This ensures the same client gets the same order of results
func ShuffleRecordsConsistently(records []string, clientIP net.IP) []string {
	if len(records) <= 1 {
		return records
	}
	
	// Create hash from client IP
	hash := md5.Sum(clientIP)
	seed := int64(binary.BigEndian.Uint64(hash[:8]))
	
	// Create new random source with consistent seed
	r := rand.New(rand.NewSource(seed))
	
	// Shuffle
	shuffled := make([]string, len(records))
	copy(shuffled, records)
	r.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	
	return shuffled
}

// RoutingMetrics tracks routing policy performance
type RoutingMetrics struct {
	TotalQueries      int64
	RoutingPolicyCounts map[RoutingPolicy]int64
	FailoverCount     int64
	AvgResponseTimeMS float64
	mu                sync.RWMutex
}

// NewRoutingMetrics creates a new metrics tracker
func NewRoutingMetrics() *RoutingMetrics {
	return &RoutingMetrics{
		RoutingPolicyCounts: make(map[RoutingPolicy]int64),
	}
}

// RecordQuery records a query execution
func (m *RoutingMetrics) RecordQuery(policy RoutingPolicy, responseTime time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.TotalQueries++
	m.RoutingPolicyCounts[policy]++
	
	// Update average response time
	alpha := 0.1 // Exponential moving average factor
	newAvg := float64(responseTime.Milliseconds())
	m.AvgResponseTimeMS = (1-alpha)*m.AvgResponseTimeMS + alpha*newAvg
}

// RecordFailover records a failover event
func (m *RoutingMetrics) RecordFailover() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FailoverCount++
}

// GetMetrics returns current metrics
func (m *RoutingMetrics) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	policyCounts := make(map[string]int64)
	for policy, count := range m.RoutingPolicyCounts {
		policyCounts[string(policy)] = count
	}
	
	return map[string]interface{}{
		"total_queries":        m.TotalQueries,
		"policy_counts":        policyCounts,
		"failover_count":       m.FailoverCount,
		"avg_response_time_ms": m.AvgResponseTimeMS,
	}
}