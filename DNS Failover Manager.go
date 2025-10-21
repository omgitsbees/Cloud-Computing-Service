package failover

import (
	"fmt"
	"sync"
	"time"
)

// RoutingPolicy defines how traffic is routed
type RoutingPolicy string

const (
	// PolicyFailover routes to primary, fails over to secondary
	PolicyFailover RoutingPolicy = "FAILOVER"
	// PolicyWeighted distributes traffic based on weights
	PolicyWeighted RoutingPolicy = "WEIGHTED"
	// PolicyGeolocation routes based on geographic location
	PolicyGeolocation RoutingPolicy = "GEOLOCATION"
	// PolicyLatency routes to lowest latency endpoint
	PolicyLatency RoutingPolicy = "LATENCY"
	// PolicyMultiValue returns multiple healthy IPs
	PolicyMultiValue RoutingPolicy = "MULTIVALUE"
)

// ResourceRecord represents a DNS resource record with health check
type ResourceRecord struct {
	ID           string
	Name         string
	Type         string // A, AAAA, CNAME, etc.
	Value        string // IP address or hostname
	TTL          int
	HealthCheckID string
	SetID        string // For routing policies
	Weight       int    // For weighted routing
	Priority     int    // For failover routing (lower is higher priority)
	Region       string // For latency/geo routing
	IsHealthy    bool
	LastUpdated  time.Time
}

// RecordSet represents a group of records that can fail over
type RecordSet struct {
	Name          string
	Type          string
	Policy        RoutingPolicy
	Records       []*ResourceRecord
	HealthChecker HealthCheckInterface
	mu            sync.RWMutex
}

// HealthCheckInterface defines the interface for health checking
type HealthCheckInterface interface {
	GetEndpointStatus(checkID string) (string, error)
}

// FailoverManager manages DNS failover logic
type FailoverManager struct {
	recordSets    map[string]*RecordSet // key: name+type
	healthChecker HealthCheckInterface
	mu            sync.RWMutex
	metrics       *FailoverMetrics
}

// FailoverMetrics tracks failover events
type FailoverMetrics struct {
	TotalFailovers     int64
	FailoversByRecord  map[string]int64
	LastFailoverTime   map[string]time.Time
	mu                 sync.RWMutex
}

// NewFailoverManager creates a new failover manager
func NewFailoverManager(healthChecker HealthCheckInterface) *FailoverManager {
	return &FailoverManager{
		recordSets:    make(map[string]*RecordSet),
		healthChecker: healthChecker,
		metrics: &FailoverMetrics{
			FailoversByRecord: make(map[string]int64),
			LastFailoverTime:  make(map[string]time.Time),
		},
	}
}

// AddRecordSet adds a new record set with failover configuration
func (fm *FailoverManager) AddRecordSet(name, recordType string, policy RoutingPolicy, records []*ResourceRecord) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	key := makeKey(name, recordType)
	
	if _, exists := fm.recordSets[key]; exists {
		return fmt.Errorf("record set %s already exists", key)
	}

	// Validate records based on policy
	if err := fm.validateRecords(policy, records); err != nil {
		return err
	}

	recordSet := &RecordSet{
		Name:          name,
		Type:          recordType,
		Policy:        policy,
		Records:       records,
		HealthChecker: fm.healthChecker,
	}

	fm.recordSets[key] = recordSet

	// Start monitoring health for records with health checks
	go fm.monitorRecordSetHealth(recordSet)

	return nil
}

// RemoveRecordSet removes a record set
func (fm *FailoverManager) RemoveRecordSet(name, recordType string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	key := makeKey(name, recordType)
	
	if _, exists := fm.recordSets[key]; !exists {
		return fmt.Errorf("record set %s not found", key)
	}

	delete(fm.recordSets, key)
	return nil
}

// GetActiveRecords returns the currently active records based on health and policy
func (fm *FailoverManager) GetActiveRecords(name, recordType string) ([]*ResourceRecord, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	key := makeKey(name, recordType)
	recordSet, exists := fm.recordSets[key]
	
	if !exists {
		return nil, fmt.Errorf("record set %s not found", key)
	}

	recordSet.mu.RLock()
	defer recordSet.mu.RUnlock()

	switch recordSet.Policy {
	case PolicyFailover:
		return fm.getFailoverRecords(recordSet), nil
	case PolicyWeighted:
		return fm.getWeightedRecords(recordSet), nil
	case PolicyLatency:
		return fm.getLatencyRecords(recordSet), nil
	case PolicyMultiValue:
		return fm.getMultiValueRecords(recordSet), nil
	default:
		return fm.getAllHealthyRecords(recordSet), nil
	}
}

// getFailoverRecords returns records based on failover priority
func (fm *FailoverManager) getFailoverRecords(recordSet *RecordSet) []*ResourceRecord {
	// Sort by priority (lower number = higher priority)
	sortedRecords := make([]*ResourceRecord, len(recordSet.Records))
	copy(sortedRecords, recordSet.Records)
	
	// Simple bubble sort by priority
	for i := 0; i < len(sortedRecords)-1; i++ {
		for j := 0; j < len(sortedRecords)-i-1; j++ {
			if sortedRecords[j].Priority > sortedRecords[j+1].Priority {
				sortedRecords[j], sortedRecords[j+1] = sortedRecords[j+1], sortedRecords[j]
			}
		}
	}

	// Return the first healthy record
	for _, record := range sortedRecords {
		if record.IsHealthy {
			return []*ResourceRecord{record}
		}
	}

	// If no healthy records, return the highest priority (even if unhealthy)
	if len(sortedRecords) > 0 {
		return []*ResourceRecord{sortedRecords[0]}
	}

	return []*ResourceRecord{}
}

// getWeightedRecords returns records based on weighted routing
func (fm *FailoverManager) getWeightedRecords(recordSet *RecordSet) []*ResourceRecord {
	healthyRecords := make([]*ResourceRecord, 0)
	
	for _, record := range recordSet.Records {
		if record.IsHealthy && record.Weight > 0 {
			healthyRecords = append(healthyRecords, record)
		}
	}

	if len(healthyRecords) == 0 {
		return []*ResourceRecord{}
	}

	// For DNS responses, we return all healthy weighted records
	// The actual selection happens at the client/resolver level
	return healthyRecords
}

// getLatencyRecords returns records sorted by latency
func (fm *FailoverManager) getLatencyRecords(recordSet *RecordSet) []*ResourceRecord {
	healthyRecords := make([]*ResourceRecord, 0)
	
	for _, record := range recordSet.Records {
		if record.IsHealthy {
			healthyRecords = append(healthyRecords, record)
		}
	}

	// In a real implementation, this would consider actual latency measurements
	// For now, return the first healthy record from the preferred region
	if len(healthyRecords) > 0 {
		return []*ResourceRecord{healthyRecords[0]}
	}

	return []*ResourceRecord{}
}

// getMultiValueRecords returns multiple healthy records
func (fm *FailoverManager) getMultiValueRecords(recordSet *RecordSet) []*ResourceRecord {
	return fm.getAllHealthyRecords(recordSet)
}

// getAllHealthyRecords returns all healthy records
func (fm *FailoverManager) getAllHealthyRecords(recordSet *RecordSet) []*ResourceRecord {
	healthyRecords := make([]*ResourceRecord, 0)
	
	for _, record := range recordSet.Records {
		if record.IsHealthy {
			healthyRecords = append(healthyRecords, record)
		}
	}

	return healthyRecords
}

// monitorRecordSetHealth continuously monitors record health
func (fm *FailoverManager) monitorRecordSetHealth(recordSet *RecordSet) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		recordSet.mu.Lock()
		
		for _, record := range recordSet.Records {
			if record.HealthCheckID != "" {
				status, err := fm.healthChecker.GetEndpointStatus(record.HealthCheckID)
				
				oldHealth := record.IsHealthy
				newHealth := (err == nil && status == "HEALTHY")
				
				record.IsHealthy = newHealth
				record.LastUpdated = time.Now()

				// Track failover event
				if oldHealth && !newHealth {
					fm.recordFailoverEvent(record)
				}
			} else {
				// No health check configured, assume healthy
				record.IsHealthy = true
			}
		}
		
		recordSet.mu.Unlock()
	}
}

// recordFailoverEvent records a failover event in metrics
func (fm *FailoverManager) recordFailoverEvent(record *ResourceRecord) {
	fm.metrics.mu.Lock()
	defer fm.metrics.mu.Unlock()

	fm.metrics.TotalFailovers++
	fm.metrics.FailoversByRecord[record.ID]++
	fm.metrics.LastFailoverTime[record.ID] = time.Now()
}

// GetMetrics returns current failover metrics
func (fm *FailoverManager) GetMetrics() *FailoverMetrics {
	fm.metrics.mu.RLock()
	defer fm.metrics.mu.RUnlock()

	// Return a copy to avoid race conditions
	return &FailoverMetrics{
		TotalFailovers:     fm.metrics.TotalFailovers,
		FailoversByRecord:  copyMap(fm.metrics.FailoversByRecord),
		LastFailoverTime:   copyTimeMap(fm.metrics.LastFailoverTime),
	}
}

// validateRecords validates records based on routing policy
func (fm *FailoverManager) validateRecords(policy RoutingPolicy, records []*ResourceRecord) error {
	if len(records) == 0 {
		return fmt.Errorf("at least one record is required")
	}

	switch policy {
	case PolicyFailover:
		// Check that priorities are set
		for _, record := range records {
			if record.Priority < 0 {
				return fmt.Errorf("failover policy requires priority to be set")
			}
		}
	case PolicyWeighted:
		// Check that weights are set
		totalWeight := 0
		for _, record := range records {
			if record.Weight < 0 {
				return fmt.Errorf("weighted policy requires non-negative weights")
			}
			totalWeight += record.Weight
		}
		if totalWeight == 0 {
			return fmt.Errorf("weighted policy requires at least one record with weight > 0")
		}
	}

	return nil
}

// GetRecordSetHealth returns health status for all records in a set
func (fm *FailoverManager) GetRecordSetHealth(name, recordType string) (map[string]bool, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	key := makeKey(name, recordType)
	recordSet, exists := fm.recordSets[key]
	
	if !exists {
		return nil, fmt.Errorf("record set %s not found", key)
	}

	recordSet.mu.RLock()
	defer recordSet.mu.RUnlock()

	healthMap := make(map[string]bool)
	for _, record := range recordSet.Records {
		healthMap[record.ID] = record.IsHealthy
	}

	return healthMap, nil
}

// Helper functions
func makeKey(name, recordType string) string {
	return fmt.Sprintf("%s:%s", name, recordType)
}

func copyMap(m map[string]int64) map[string]int64 {
	result := make(map[string]int64)
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyTimeMap(m map[string]time.Time) map[string]time.Time {
	result := make(map[string]time.Time)
	for k, v := range m {
		result[k] = v
	}
	return result
}