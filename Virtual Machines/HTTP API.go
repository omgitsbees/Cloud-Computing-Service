package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/yourorg/cloud/compute"
)

// InstanceTypeHandler handles HTTP requests for instance types
type InstanceTypeHandler struct {
	service *compute.InstanceTypeService
}

func NewInstanceTypeHandler(service *compute.InstanceTypeService) *InstanceTypeHandler {
	return &InstanceTypeHandler{service: service}
}

// RegisterRoutes registers all instance type routes
func (h *InstanceTypeHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/instance-types", h.ListInstanceTypes).Methods("GET")
	r.HandleFunc("/instance-types/{name}", h.GetInstanceType).Methods("GET")
	r.HandleFunc("/instance-types/recommend", h.GetRecommendations).Methods("POST")
	r.HandleFunc("/instance-types/compare", h.CompareInstanceTypes).Methods("POST")
	r.HandleFunc("/instance-types/{name}/pricing", h.GetPricing).Methods("GET")
	r.HandleFunc("/instance-types/families/{family}", h.GetInstanceTypesByFamily).Methods("GET")
}

// ListInstanceTypes godoc
// @Summary List all available instance types
// @Description Get a list of all instance types with optional filtering
// @Tags instance-types
// @Accept json
// @Produce json
// @Param family query string false "Instance family filter"
// @Param min_vcpus query int false "Minimum vCPUs"
// @Param max_vcpus query int false "Maximum vCPUs"
// @Param min_memory_gb query number false "Minimum memory in GB"
// @Param max_memory_gb query number false "Maximum memory in GB"
// @Param architecture query string false "CPU architecture (x86_64, arm64)"
// @Param region query string false "Region code"
// @Param gpu_required query bool false "Require GPU"
// @Param burstable query bool false "Burstable instances only"
// @Param max_price_cents query int false "Maximum price in cents per hour"
// @Success 200 {array} compute.InstanceType
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /instance-types [get]
func (h *InstanceTypeHandler) ListInstanceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	filter := &compute.InstanceTypeFilter{}

	if family := r.URL.Query().Get("family"); family != "" {
		f := compute.InstanceFamily(family)
		filter.Family = &f
	}

	if minVCPUs := r.URL.Query().Get("min_vcpus"); minVCPUs != "" {
		v, err := strconv.Atoi(minVCPUs)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid min_vcpus parameter")
			return
		}
		filter.MinVCPUs = &v
	}

	if maxVCPUs := r.URL.Query().Get("max_vcpus"); maxVCPUs != "" {
		v, err := strconv.Atoi(maxVCPUs)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid max_vcpus parameter")
			return
		}
		filter.MaxVCPUs = &v
	}

	if minMemory := r.URL.Query().Get("min_memory_gb"); minMemory != "" {
		v, err := strconv.ParseFloat(minMemory, 64)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid min_memory_gb parameter")
			return
		}
		filter.MinMemoryGB = &v
	}

	if maxMemory := r.URL.Query().Get("max_memory_gb"); maxMemory != "" {
		v, err := strconv.ParseFloat(maxMemory, 64)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid max_memory_gb parameter")
			return
		}
		filter.MaxMemoryGB = &v
	}

	if arch := r.URL.Query().Get("architecture"); arch != "" {
		a := compute.Architecture(arch)
		filter.Architecture = &a
	}

	if region := r.URL.Query().Get("region"); region != "" {
		filter.Region = &region
	}

	if gpuRequired := r.URL.Query().Get("gpu_required"); gpuRequired != "" {
		v, err := strconv.ParseBool(gpuRequired)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid gpu_required parameter")
			return
		}
		filter.GPURequired = &v
	}

	if burstable := r.URL.Query().Get("burstable"); burstable != "" {
		v, err := strconv.ParseBool(burstable)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid burstable parameter")
			return
		}
		filter.Burstable = &v
	}

	if maxPrice := r.URL.Query().Get("max_price_cents"); maxPrice != "" {
		v, err := strconv.ParseInt(maxPrice, 10, 64)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid max_price_cents parameter")
			return
		}
		filter.MaxPriceCents = &v
	}

	// Get instance types
	types, err := h.service.GetRecommendedInstanceTypes(ctx, *filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to retrieve instance types")
		return
	}

	respondJSON(w, http.StatusOK, types)
}

// GetInstanceType godoc
// @Summary Get instance type details
// @Description Get detailed information about a specific instance type
// @Tags instance-types
// @Accept json
// @Produce json
// @Param name path string true "Instance type name (e.g., m5.large)"
// @Success 200 {object} compute.InstanceType
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /instance-types/{name} [get]
func (h *InstanceTypeHandler) GetInstanceType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	name := vars["name"]

	instanceType, err := h.service.repo.GetInstanceType(ctx, name)
	if err != nil {
		respondError(w, http.StatusNotFound, "instance type not found")
		return
	}

	respondJSON(w, http.StatusOK, instanceType)
}

// RecommendationRequest represents a request for instance type recommendations
type RecommendationRequest struct {
	MinVCPUs      *int                    `json:"min_vcpus,omitempty"`
	MinMemoryGB   *float64                `json:"min_memory_gb,omitempty"`
	MaxPriceCents *int64                  `json:"max_price_cents,omitempty"`
	Region        *string                 `json:"region,omitempty"`
	Family        *compute.InstanceFamily `json:"family,omitempty"`
	Architecture  *compute.Architecture   `json:"architecture,omitempty"`
	GPURequired   *bool                   `json:"gpu_required,omitempty"`
	Workload      string                  `json:"workload,omitempty"` // web, database, ml, etc.
}

// GetRecommendations godoc
// @Summary Get instance type recommendations
// @Description Get recommended instance types based on requirements
// @Tags instance-types
// @Accept json
// @Produce json
// @Param request body RecommendationRequest true "Recommendation criteria"
// @Success 200 {array} compute.InstanceType
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /instance-types/recommend [post]
func (h *InstanceTypeHandler) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RecommendationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build filter from request
	filter := compute.InstanceTypeFilter{
		MinVCPUs:      req.MinVCPUs,
		MinMemoryGB:   req.MinMemoryGB,
		MaxPriceCents: req.MaxPriceCents,
		Region:        req.Region,
		Family:        req.Family,
		Architecture:  req.Architecture,
		GPURequired:   req.GPURequired,
	}

	// Apply workload-based recommendations
	if req.Workload != "" {
		applyWorkloadRecommendations(&filter, req.Workload)
	}

	types, err := h.service.GetRecommendedInstanceTypes(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get recommendations")
		return
	}

	respondJSON(w, http.StatusOK, types)
}

// CompareRequest represents a request to compare instance types
type CompareRequest struct {
	InstanceTypes []string `json:"instance_types"`
}

// CompareInstanceTypes godoc
// @Summary Compare instance types
// @Description Compare multiple instance types side by side
// @Tags instance-types
// @Accept json
// @Produce json
// @Param request body CompareRequest true "Instance types to compare"
// @Success 200 {object} map[string]compute.InstanceType
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /instance-types/compare [post]
func (h *InstanceTypeHandler) CompareInstanceTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.InstanceTypes) == 0 {
		respondError(w, http.StatusBadRequest, "no instance types provided")
		return
	}

	if len(req.InstanceTypes) > 10 {
		respondError(w, http.StatusBadRequest, "cannot compare more than 10 instance types")
		return
	}

	comparison, err := h.service.CompareInstanceTypes(ctx, req.InstanceTypes)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, comparison)
}

// PricingResponse represents pricing information for an instance type
type PricingResponse struct {
	InstanceType    string  `json:"instance_type"`
	OnDemandHourly  float64 `json:"on_demand_hourly"`
	OnDemandMonthly float64 `json:"on_demand_monthly"`
	SpotHourly      float64 `json:"spot_hourly"`
	SpotMonthly     float64 `json:"spot_monthly"`
	Currency        string  `json:"currency"`
}

// GetPricing godoc
// @Summary Get instance type pricing
// @Description Get pricing information for a specific instance type
// @Tags instance-types
// @Accept json
// @Produce json
// @Param name path string true "Instance type name"
// @Success 200 {object} PricingResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /instance-types/{name}/pricing [get]
func (h *InstanceTypeHandler) GetPricing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	name := vars["name"]

	onDemandHourly, err := h.service.CalculateHourlyCost(ctx, name, false)
	if err != nil {
		respondError(w, http.StatusNotFound, "instance type not found")
		return
	}

	spotHourly, err := h.service.CalculateHourlyCost(ctx, name, true)
	if err != nil {
		respondError(w, http.StatusNotFound, "instance type not found")
		return
	}

	response := PricingResponse{
		InstanceType:    name,
		OnDemandHourly:  float64(onDemandHourly) / 100.0,
		OnDemandMonthly: float64(onDemandHourly*730) / 100.0,
		SpotHourly:      float64(spotHourly) / 100.0,
		SpotMonthly:     float64(spotHourly*730) / 100.0,
		Currency:        "USD",
	}

	respondJSON(w, http.StatusOK, response)
}

// GetInstanceTypesByFamily godoc
// @Summary Get instance types by family
// @Description Get all instance types in a specific family
// @Tags instance-types
// @Accept json
// @Produce json
// @Param family path string true "Instance family (general, compute, memory, storage, gpu, fpga)"
// @Success 200 {array} compute.InstanceType
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /instance-types/families/{family} [get]
func (h *InstanceTypeHandler) GetInstanceTypesByFamily(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	family := compute.InstanceFamily(vars["family"])

	// Validate family
	validFamilies := map[compute.InstanceFamily]bool{
		compute.FamilyGeneralPurpose:   true,
		compute.FamilyComputeOptimized: true,
		compute.FamilyMemoryOptimized:  true,
		compute.FamilyStorageOptimized: true,
		compute.FamilyGPUAccelerated:   true,
		compute.FamilyFPGAAccelerated:  true,
	}

	if !validFamilies[family] {
		respondError(w, http.StatusBadRequest, "invalid instance family")
		return
	}

	types, err := h.service.GetInstanceTypesByFamily(ctx, family)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to retrieve instance types")
		return
	}

	respondJSON(w, http.StatusOK, types)
}

// applyWorkloadRecommendations adjusts the filter based on workload type
func applyWorkloadRecommendations(filter *compute.InstanceTypeFilter, workload string) {
	workload = strings.ToLower(workload)

	switch workload {
	case "web", "api":
		// Web servers: balanced instances, burstable for low traffic
		family := compute.FamilyGeneralPurpose
		filter.Family = &family

	case "database", "cache":
		// Databases: memory optimized
		family := compute.FamilyMemoryOptimized
		filter.Family = &family

	case "compute", "batch", "encoding":
		// CPU intensive: compute optimized
		family := compute.FamilyComputeOptimized
		filter.Family = &family

	case "ml", "ai", "training":
		// Machine learning: GPU instances
		family := compute.FamilyGPUAccelerated
		filter.Family = &family
		gpuRequired := true
		filter.GPURequired = &gpuRequired

	case "storage", "backup":
		// Storage workloads: storage optimized
		family := compute.FamilyStorageOptimized
		filter.Family = &family
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}
