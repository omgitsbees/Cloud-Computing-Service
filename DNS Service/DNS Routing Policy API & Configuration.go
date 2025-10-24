package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// RoutingPolicyService manages routing policies
type RoutingPolicyService struct {
	db            *sql.DB
	policyEngine  *RoutingPolicyEngine
	metrics       *RoutingMetrics
}

// NewRoutingPolicyService creates a new routing policy service
func NewRoutingPolicyService(db *sql.DB, engine *RoutingPolicyEngine) *RoutingPolicyService {
	return &RoutingPolicyService{
		db:           db,
		policyEngine: engine,
		metrics:      NewRoutingMetrics(),
	}
}

// CreateRoutingPolicyRequest represents a request to create a routing policy
type CreateRoutingPolicyRequest struct {
	HostedZoneID  string              `json:"hosted_zone_id"`
	Name          string              `json:"name"`
	Type          string              `json:"type"`
	TTL           uint32              `json:"ttl"`
	RoutingPolicy RoutingPolicy       `json:"routing_policy"`
	Records       []RecordSetConfig   `json:"records"`
	HealthCheckID string              `json:"health_check_id,omitempty"`
}

// RecordSetConfig represents configuration for a record set
type RecordSetConfig struct {
	Values          []string        `json:"values"`
	Weight          int64           `json:"weight,omitempty"`
	Region          string          `json:"region,omitempty"`
	Priority        int             `json:"priority,omitempty"`
	HealthCheckID   string          `json:"health_check_id,omitempty"`
	GeoLocation     *GeoLocation    `json:"geo_location,omitempty"`
	Coordinates     *Coordinates    `json:"coordinates,omitempty"`
	Bias            int             `json:"bias,omitempty"`
	IPRanges        []string        `json:"ip_ranges,omitempty"`
	SetIdentifier   string          `json:"set_identifier"`
}

// RoutingPolicyResponse represents the API response
type RoutingPolicyResponse struct {
	ID            string            `json:"id"`
	HostedZoneID  string            `json:"hosted_zone_id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	TTL           uint32            `json:"ttl"`
	RoutingPolicy RoutingPolicy     `json:"routing_policy"`
	Records       []RecordSetConfig `json:"records"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// RegisterHandlers registers HTTP handlers for routing policies
func (s *RoutingPolicyService) RegisterHandlers(r *mux.Router) {
	r.HandleFunc("/routing-policies", s.CreateRoutingPolicy).Methods("POST")
	r.HandleFunc("/routing-policies/{id}", s.GetRoutingPolicy).Methods("GET")
	r.HandleFunc("/routing-policies/{id}", s.UpdateRoutingPolicy).Methods("PUT")
	r.HandleFunc("/routing-policies/{id}", s.DeleteRoutingPolicy).Methods("DELETE")
	r.HandleFunc("/routing-policies", s.ListRoutingPolicies).Methods("GET")
	r.HandleFunc("/routing-policies/test", s.TestRouting).Methods("POST")
	r.HandleFunc("/routing-policies/metrics", s.GetMetrics).Methods("GET")
}

// CreateRoutingPolicy creates a new routing policy
func (s *RoutingPolicyService) CreateRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	var req CreateRoutingPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request
	if err := s.validateRoutingPolicy(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Store in database
	ctx := r.Context()
	policyID, err := s.storeRoutingPolicy(ctx, &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve and return created policy
	policy, err := s.getRoutingPolicyByID(ctx, policyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

// GetRoutingPolicy retrieves a routing policy by ID
func (s *RoutingPolicyService) GetRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	ctx := r.Context()
	policy, err := s.getRoutingPolicyByID(ctx, policyID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "routing policy not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// UpdateRoutingPolicy updates an existing routing policy
func (s *RoutingPolicyService) UpdateRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	var req CreateRoutingPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.validateRoutingPolicy(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := s.updateRoutingPolicy(ctx, policyID, &req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	policy, err := s.getRoutingPolicyByID(ctx, policyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// DeleteRoutingPolicy deletes a routing policy
func (s *RoutingPolicyService) DeleteRoutingPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	ctx := r.Context()
	if err := s.deleteRoutingPolicy(ctx, policyID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListRoutingPolicies lists all routing policies
func (s *RoutingPolicyService) ListRoutingPolicies(w http.ResponseWriter, r *http.Request) {
	hostedZoneID := r.URL.Query().Get("hosted_zone_id")

	ctx := r.Context()
	policies, err := s.listRoutingPolicies(ctx, hostedZoneID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	})
}

// TestRoutingRequest represents a request to test routing
type TestRoutingRequest struct {
	PolicyID string `json:"policy_id"`
	ClientIP string `json:"client_ip"`
}

// TestRouting tests routing policy resolution
func (s *RoutingPolicyService) TestRouting(w http.ResponseWriter, r *http.Request) {
	var req TestRoutingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientIP := net.ParseIP(req.ClientIP)
	if clientIP == nil {
		http.Error(w, "invalid client IP", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	policy, err := s.getRoutingPolicyByID(ctx, req.PolicyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to RoutingRecord
	record := s.convertToRoutingRecord(policy)

	// Test routing
	startTime := time.Now()
	values, err := s.policyEngine.RouteQuery(ctx, record, clientIP)
	duration := time.Since(startTime)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Record metrics
	s.metrics.RecordQuery(policy.RoutingPolicy, duration)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policy_id":       req.PolicyID,
		"client_ip":       req.ClientIP,
		"routing_policy":  policy.RoutingPolicy,
		"resolved_values": values,
		"response_time_ms": duration.Milliseconds(),
	})
}

// GetMetrics returns routing metrics
func (s *RoutingPolicyService) GetMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.metrics.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Database operations

func (s *RoutingPolicyService) storeRoutingPolicy(ctx context.Context, req *CreateRoutingPolicyRequest) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// Generate policy ID
	policyID := generateID("rp")

	// Insert main routing policy
	_, err = tx.ExecContext(ctx, `
		INSERT INTO routing_policies (
			id, hosted_zone_id, name, type, ttl, routing_policy, health_check_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, policyID, req.HostedZoneID, req.Name, req.Type, req.TTL, req.RoutingPolicy, req.HealthCheckID, time.Now(), time.Now())
	if err != nil {
		return "", err
	}

	// Insert record sets
	for _, record := range req.Records {
		recordSetID := generateID("rs")
		
		geoLocationJSON, _ := json.Marshal(record.GeoLocation)
		coordinatesJSON, _ := json.Marshal(record.Coordinates)
		valuesJSON, _ := json.Marshal(record.Values)
		ipRangesJSON, _ := json.Marshal(record.IPRanges)

		_, err = tx.ExecContext(ctx, `
			INSERT INTO routing_policy_record_sets (
				id, routing_policy_id, values, weight, region, priority, 
				health_check_id, geo_location, coordinates, bias, ip_ranges, set_identifier
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`, recordSetID, policyID, valuesJSON, record.Weight, record.Region, record.Priority,
			record.HealthCheckID, geoLocationJSON, coordinatesJSON, record.Bias, ipRangesJSON, record.SetIdentifier)
		if err != nil {
			return "", err
		}
	}

	if err = tx.Commit(); err != nil {
		return "", err
	}

	return policyID, nil
}

func (s *RoutingPolicyService) getRoutingPolicyByID(ctx context.Context, policyID string) (*RoutingPolicyResponse, error) {
	var policy RoutingPolicyResponse

	err := s.db.QueryRowContext(ctx, `
		SELECT id, hosted_zone_id, name, type, ttl, routing_policy, created_at, updated_at
		FROM routing_policies
		WHERE id = $1
	`, policyID).Scan(
		&policy.ID, &policy.HostedZoneID, &policy.Name, &policy.Type,
		&policy.TTL, &policy.RoutingPolicy, &policy.CreatedAt, &policy.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Fetch record sets
	rows, err := s.db.QueryContext(ctx, `
		SELECT values, weight, region, priority, health_check_id, 
			   geo_location, coordinates, bias, ip_ranges, set_identifier
		FROM routing_policy_record_sets
		WHERE routing_policy_id = $1
	`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policy.Records = []RecordSetConfig{}
	for rows.Next() {
		var record RecordSetConfig
		var valuesJSON, geoLocationJSON, coordinatesJSON, ipRangesJSON []byte

		err := rows.Scan(
			&valuesJSON, &record.Weight, &record.Region, &record.Priority,
			&record.HealthCheckID, &geoLocationJSON, &coordinatesJSON,
			&record.Bias, &ipRangesJSON, &record.SetIdentifier,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(valuesJSON, &record.Values)
		if len(geoLocationJSON) > 0 {
			json.Unmarshal(geoLocationJSON, &record.GeoLocation)
		}
		if len(coordinatesJSON) > 0 {
			json.Unmarshal(coordinatesJSON, &record.Coordinates)
		}
		if len(ipRangesJSON) > 0 {
			json.Unmarshal(ipRangesJSON, &record.IPRanges)
		}

		policy.Records = append(policy.Records, record)
	}

	return &policy, nil
}

func (s *RoutingPolicyService) updateRoutingPolicy(ctx context.Context, policyID string, req *CreateRoutingPolicyRequest) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update main policy
	_, err = tx.ExecContext(ctx, `
		UPDATE routing_policies
		SET hosted_zone_id = $1, name = $2, type = $3, ttl = $4, 
		    routing_policy = $5, health_check_id = $6, updated_at = $7
		WHERE id = $8
	`, req.HostedZoneID, req.Name, req.Type, req.TTL, req.RoutingPolicy, req.HealthCheckID, time.Now(), policyID)
	if err != nil {
		return err
	}

	// Delete existing record sets
	_, err = tx.ExecContext(ctx, `
		DELETE FROM routing_policy_record_sets WHERE routing_policy_id = $1
	`, policyID)
	if err != nil {
		return err
	}

	// Insert new record sets
	for _, record := range req.Records {
		recordSetID := generateID("rs")
		
		geoLocationJSON, _ := json.Marshal(record.GeoLocation)
		coordinatesJSON, _ := json.Marshal(record.Coordinates)
		valuesJSON, _ := json.Marshal(record.Values)
		ipRangesJSON, _ := json.Marshal(record.IPRanges)

		_, err = tx.ExecContext(ctx, `
			INSERT INTO routing_policy_record_sets (
				id, routing_policy_id, values, weight, region, priority,
				health_check_id, geo_location, coordinates, bias, ip_ranges, set_identifier
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`, recordSetID, policyID, valuesJSON, record.Weight, record.Region, record.Priority,
			record.HealthCheckID, geoLocationJSON, coordinatesJSON, record.Bias, ipRangesJSON, record.SetIdentifier)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *RoutingPolicyService) deleteRoutingPolicy(ctx context.Context, policyID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete record sets
	_, err = tx.ExecContext(ctx, `
		DELETE FROM routing_policy_record_sets WHERE routing_policy_id = $1
	`, policyID)
	if err != nil {
		return err
	}

	// Delete policy
	_, err = tx.ExecContext(ctx, `
		DELETE FROM routing_policies WHERE id = $1
	`, policyID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *RoutingPolicyService) listRoutingPolicies(ctx context.Context, hostedZoneID string) ([]*RoutingPolicyResponse, error) {
	query := `
		SELECT id, hosted_zone_id, name, type, ttl, routing_policy, created_at, updated_at
		FROM routing_policies
	`
	args := []interface{}{}

	if hostedZoneID != "" {
		query += " WHERE hosted_zone_id = $1"
		args = append(args, hostedZoneID)
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := []*RoutingPolicyResponse{}
	for rows.Next() {
		var policy RoutingPolicyResponse
		err := rows.Scan(
			&policy.ID, &policy.HostedZoneID, &policy.Name, &policy.Type,
			&policy.TTL, &policy.RoutingPolicy, &policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Fetch record sets for this policy
		recordSets, err := s.getRecordSets(ctx, policy.ID)
		if err != nil {
			return nil, err
		}
		policy.Records = recordSets

		policies = append(policies, &policy)
	}

	return policies, nil
}

func (s *RoutingPolicyService) getRecordSets(ctx context.Context, policyID string) ([]RecordSetConfig, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT values, weight, region, priority, health_check_id,
		       geo_location, coordinates, bias, ip_ranges, set_identifier
		FROM routing_policy_record_sets
		WHERE routing_policy_id = $1
	`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []RecordSetConfig{}
	for rows.Next() {
		var record RecordSetConfig
		var valuesJSON, geoLocationJSON, coordinatesJSON, ipRangesJSON []byte

		err := rows.Scan(
			&valuesJSON, &record.Weight, &record.Region, &record.Priority,
			&record.HealthCheckID, &geoLocationJSON, &coordinatesJSON,
			&record.Bias, &ipRangesJSON, &record.SetIdentifier,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(valuesJSON, &record.Values)
		if len(geoLocationJSON) > 0 {
			json.Unmarshal(geoLocationJSON, &record.GeoLocation)
		}
		if len(coordinatesJSON) > 0 {
			json.Unmarshal(coordinatesJSON, &record.Coordinates)
		}
		if len(ipRangesJSON) > 0 {
			json.Unmarshal(ipRangesJSON, &record.IPRanges)
		}

		records = append(records, record)
	}

	return records, nil
}

// Helper functions

func (s *RoutingPolicyService) validateRoutingPolicy(req *CreateRoutingPolicyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.Type == "" {
		return fmt.Errorf("type is required")
	}
	if len(req.Records) == 0 {
		return fmt.Errorf("at least one record is required")
	}

	// Validate based on routing policy type
	switch req.RoutingPolicy {
	case PolicyWeighted:
		for i, record := range req.Records {
			if record.Weight <= 0 {
				return fmt.Errorf("record %d: weight must be positive for weighted routing", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for weighted routing", i)
			}
		}

	case PolicyLatency:
		for i, record := range req.Records {
			if record.Region == "" {
				return fmt.Errorf("record %d: region is required for latency routing", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for latency routing", i)
			}
		}

	case PolicyFailover:
		for i, record := range req.Records {
			if record.Priority < 0 {
				return fmt.Errorf("record %d: priority must be non-negative for failover routing", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for failover routing", i)
			}
		}

	case PolicyGeolocation:
		for i, record := range req.Records {
			if record.GeoLocation == nil && record.SetIdentifier != "default" {
				return fmt.Errorf("record %d: geo_location is required for geolocation routing (or use 'default' as set_identifier)", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for geolocation routing", i)
			}
		}

	case PolicyGeoproximity:
		for i, record := range req.Records {
			if record.Coordinates == nil {
				return fmt.Errorf("record %d: coordinates are required for geoproximity routing", i)
			}
			if record.Bias < -99 || record.Bias > 99 {
				return fmt.Errorf("record %d: bias must be between -99 and 99", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for geoproximity routing", i)
			}
		}

	case PolicyIPBased:
		for i, record := range req.Records {
			if len(record.IPRanges) == 0 && record.SetIdentifier != "default" {
				return fmt.Errorf("record %d: ip_ranges are required for IP-based routing (or use 'default' as set_identifier)", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for IP-based routing", i)
			}
		}

	case PolicyMultiValue:
		for i, record := range req.Records {
			if len(record.Values) == 0 {
				return fmt.Errorf("record %d: values are required", i)
			}
			if record.SetIdentifier == "" {
				return fmt.Errorf("record %d: set_identifier is required for multivalue routing", i)
			}
		}
	}

	return nil
}

func (s *RoutingPolicyService) convertToRoutingRecord(policy *RoutingPolicyResponse) *RoutingRecord {
	record := &RoutingRecord{
		ID:            policy.ID,
		Name:          policy.Name,
		Type:          policy.Type,
		TTL:           policy.TTL,
		RoutingPolicy: policy.RoutingPolicy,
		Records:       make([]RecordSet, len(policy.Records)),
	}

	for i, cfg := range policy.Records {
		record.Records[i] = RecordSet{
			Values:        cfg.Values,
			Weight:        cfg.Weight,
			Region:        cfg.Region,
			Priority:      cfg.Priority,
			HealthCheckID: cfg.HealthCheckID,
			GeoLocation:   cfg.GeoLocation,
			Coordinates:   cfg.Coordinates,
			Bias:          cfg.Bias,
			IPRanges:      cfg.IPRanges,
			SetIdentifier: cfg.SetIdentifier,
			Healthy:       true, // Will be checked by policy engine
		}
	}

	return record
}

func generateID(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), rand.Intn(10000))
}