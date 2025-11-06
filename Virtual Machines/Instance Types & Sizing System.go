package compute

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// InstanceFamily represents different categories of instances
type InstanceFamily string

const (
	FamilyGeneralPurpose    InstanceFamily = "general"
	FamilyComputeOptimized  InstanceFamily = "compute"
	FamilyMemoryOptimized   InstanceFamily = "memory"
	FamilyStorageOptimized  InstanceFamily = "storage"
	FamilyGPUAccelerated    InstanceFamily = "gpu"
	FamilyFPGAAccelerated   InstanceFamily = "fpga"
)

// InstanceGeneration represents the generation of instance types
type InstanceGeneration string

const (
	Generation1 InstanceGeneration = "gen1"
	Generation2 InstanceGeneration = "gen2"
	Generation3 InstanceGeneration = "gen3"
)

// Architecture represents CPU architecture
type Architecture string

const (
	ArchX86_64 Architecture = "x86_64"
	ArchARM64  Architecture = "arm64"
)

// NetworkPerformance levels
type NetworkPerformance string

const (
	NetworkLow      NetworkPerformance = "low"
	NetworkModerate NetworkPerformance = "moderate"
	NetworkHigh     NetworkPerformance = "high"
	NetworkVeryHigh NetworkPerformance = "very_high"
	Network10Gbps   NetworkPerformance = "10_gbps"
	Network25Gbps   NetworkPerformance = "25_gbps"
	Network50Gbps   NetworkPerformance = "50_gbps"
	Network100Gbps  NetworkPerformance = "100_gbps"
)

// StorageType represents the type of instance storage
type StorageType string

const (
	StorageEBS  StorageType = "ebs_only"
	StorageNVMe StorageType = "nvme_ssd"
	StorageHDD  StorageType = "hdd"
)

// InstanceType represents a complete instance type definition
type InstanceType struct {
	ID                 uuid.UUID          `json:"id"`
	Name               string             `json:"name"` // e.g., "m5.large"
	Family             InstanceFamily     `json:"family"`
	Generation         InstanceGeneration `json:"generation"`
	Size               string             `json:"size"` // nano, micro, small, medium, large, xlarge, 2xlarge, etc.
	
	// Compute specifications
	VCPUs              int                `json:"vcpus"`
	CPUCreditsPerHour  *int               `json:"cpu_credits_per_hour,omitempty"` // For burstable instances
	Architecture       Architecture       `json:"architecture"`
	ClockSpeedGHz      float64            `json:"clock_speed_ghz"`
	
	// Memory specifications
	MemoryGB           float64            `json:"memory_gb"`
	
	// Storage specifications
	StorageType        StorageType        `json:"storage_type"`
	InstanceStorageGB  int                `json:"instance_storage_gb"`
	EBSOptimized       bool               `json:"ebs_optimized"`
	EBSBandwidthMbps   int                `json:"ebs_bandwidth_mbps"`
	
	// Network specifications
	NetworkPerformance NetworkPerformance `json:"network_performance"`
	MaxNetworkCards    int                `json:"max_network_cards"`
	IPv6Supported      bool               `json:"ipv6_supported"`
	ENASupported       bool               `json:"ena_supported"` // Enhanced Networking
	
	// GPU specifications (if applicable)
	GPUs               int                `json:"gpus,omitempty"`
	GPUMemoryGB        int                `json:"gpu_memory_gb,omitempty"`
	GPUModel           string             `json:"gpu_model,omitempty"`
	
	// Additional features
	DedicatedHost      bool               `json:"dedicated_host_supported"`
	Burstable          bool               `json:"burstable"`
	HibernationSupport bool               `json:"hibernation_support"`
	
	// Pricing (per hour in cents)
	OnDemandPrice      int64              `json:"on_demand_price_cents"`
	SpotBasePrice      int64              `json:"spot_base_price_cents"`
	
	// Availability
	AvailableRegions   []string           `json:"available_regions"`
	Active             bool               `json:"active"`
	
	// Metadata
	Description        string             `json:"description"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

// InstanceTypeFilter for querying instance types
type InstanceTypeFilter struct {
	Family             *InstanceFamily     `json:"family,omitempty"`
	MinVCPUs           *int                `json:"min_vcpus,omitempty"`
	MaxVCPUs           *int                `json:"max_vcpus,omitempty"`
	MinMemoryGB        *float64            `json:"min_memory_gb,omitempty"`
	MaxMemoryGB        *float64            `json:"max_memory_gb,omitempty"`
	Architecture       *Architecture       `json:"architecture,omitempty"`
	Region             *string             `json:"region,omitempty"`
	GPURequired        *bool               `json:"gpu_required,omitempty"`
	Burstable          *bool               `json:"burstable,omitempty"`
	MaxPriceCents      *int64              `json:"max_price_cents,omitempty"`
}

// InstanceTypeRepository handles persistence of instance types
type InstanceTypeRepository struct {
	db *sql.DB
}

func NewInstanceTypeRepository(db *sql.DB) *InstanceTypeRepository {
	return &InstanceTypeRepository{db: db}
}

// CreateInstanceType creates a new instance type
func (r *InstanceTypeRepository) CreateInstanceType(ctx context.Context, it *InstanceType) error {
	query := `
		INSERT INTO instance_types (
			id, name, family, generation, size,
			vcpus, cpu_credits_per_hour, architecture, clock_speed_ghz,
			memory_gb, storage_type, instance_storage_gb, ebs_optimized, ebs_bandwidth_mbps,
			network_performance, max_network_cards, ipv6_supported, ena_supported,
			gpus, gpu_memory_gb, gpu_model,
			dedicated_host_supported, burstable, hibernation_support,
			on_demand_price_cents, spot_base_price_cents,
			available_regions, active, description,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13, $14,
			$15, $16, $17, $18,
			$19, $20, $21,
			$22, $23, $24,
			$25, $26,
			$27, $28, $29,
			$30, $31
		)
	`
	
	it.ID = uuid.New()
	it.CreatedAt = time.Now()
	it.UpdatedAt = time.Now()
	
	_, err := r.db.ExecContext(ctx, query,
		it.ID, it.Name, it.Family, it.Generation, it.Size,
		it.VCPUs, it.CPUCreditsPerHour, it.Architecture, it.ClockSpeedGHz,
		it.MemoryGB, it.StorageType, it.InstanceStorageGB, it.EBSOptimized, it.EBSBandwidthMbps,
		it.NetworkPerformance, it.MaxNetworkCards, it.IPv6Supported, it.ENASupported,
		it.GPUs, it.GPUMemoryGB, it.GPUModel,
		it.DedicatedHost, it.Burstable, it.HibernationSupport,
		it.OnDemandPrice, it.SpotBasePrice,
		pq.Array(it.AvailableRegions), it.Active, it.Description,
		it.CreatedAt, it.UpdatedAt,
	)
	
	return err
}

// GetInstanceType retrieves an instance type by name
func (r *InstanceTypeRepository) GetInstanceType(ctx context.Context, name string) (*InstanceType, error) {
	query := `
		SELECT 
			id, name, family, generation, size,
			vcpus, cpu_credits_per_hour, architecture, clock_speed_ghz,
			memory_gb, storage_type, instance_storage_gb, ebs_optimized, ebs_bandwidth_mbps,
			network_performance, max_network_cards, ipv6_supported, ena_supported,
			gpus, gpu_memory_gb, gpu_model,
			dedicated_host_supported, burstable, hibernation_support,
			on_demand_price_cents, spot_base_price_cents,
			available_regions, active, description,
			created_at, updated_at
		FROM instance_types
		WHERE name = $1 AND active = true
	`
	
	it := &InstanceType{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&it.ID, &it.Name, &it.Family, &it.Generation, &it.Size,
		&it.VCPUs, &it.CPUCreditsPerHour, &it.Architecture, &it.ClockSpeedGHz,
		&it.MemoryGB, &it.StorageType, &it.InstanceStorageGB, &it.EBSOptimized, &it.EBSBandwidthMbps,
		&it.NetworkPerformance, &it.MaxNetworkCards, &it.IPv6Supported, &it.ENASupported,
		&it.GPUs, &it.GPUMemoryGB, &it.GPUModel,
		&it.DedicatedHost, &it.Burstable, &it.HibernationSupport,
		&it.OnDemandPrice, &it.SpotBasePrice,
		pq.Array(&it.AvailableRegions), &it.Active, &it.Description,
		&it.CreatedAt, &it.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("instance type not found: %s", name)
	}
	
	return it, err
}

// ListInstanceTypes retrieves instance types with optional filtering
func (r *InstanceTypeRepository) ListInstanceTypes(ctx context.Context, filter *InstanceTypeFilter) ([]*InstanceType, error) {
	query := `
		SELECT 
			id, name, family, generation, size,
			vcpus, cpu_credits_per_hour, architecture, clock_speed_ghz,
			memory_gb, storage_type, instance_storage_gb, ebs_optimized, ebs_bandwidth_mbps,
			network_performance, max_network_cards, ipv6_supported, ena_supported,
			gpus, gpu_memory_gb, gpu_model,
			dedicated_host_supported, burstable, hibernation_support,
			on_demand_price_cents, spot_base_price_cents,
			available_regions, active, description,
			created_at, updated_at
		FROM instance_types
		WHERE active = true
	`
	
	args := []interface{}{}
	argCount := 1
	
	if filter != nil {
		if filter.Family != nil {
			query += fmt.Sprintf(" AND family = $%d", argCount)
			args = append(args, *filter.Family)
			argCount++
		}
		
		if filter.MinVCPUs != nil {
			query += fmt.Sprintf(" AND vcpus >= $%d", argCount)
			args = append(args, *filter.MinVCPUs)
			argCount++
		}
		
		if filter.MaxVCPUs != nil {
			query += fmt.Sprintf(" AND vcpus <= $%d", argCount)
			args = append(args, *filter.MaxVCPUs)
			argCount++
		}
		
		if filter.MinMemoryGB != nil {
			query += fmt.Sprintf(" AND memory_gb >= $%d", argCount)
			args = append(args, *filter.MinMemoryGB)
			argCount++
		}
		
		if filter.MaxMemoryGB != nil {
			query += fmt.Sprintf(" AND memory_gb <= $%d", argCount)
			args = append(args, *filter.MaxMemoryGB)
			argCount++
		}
		
		if filter.Architecture != nil {
			query += fmt.Sprintf(" AND architecture = $%d", argCount)
			args = append(args, *filter.Architecture)
			argCount++
		}
		
		if filter.Region != nil {
			query += fmt.Sprintf(" AND $%d = ANY(available_regions)", argCount)
			args = append(args, *filter.Region)
			argCount++
		}
		
		if filter.GPURequired != nil && *filter.GPURequired {
			query += " AND gpus > 0"
		}
		
		if filter.Burstable != nil {
			query += fmt.Sprintf(" AND burstable = $%d", argCount)
			args = append(args, *filter.Burstable)
			argCount++
		}
		
		if filter.MaxPriceCents != nil {
			query += fmt.Sprintf(" AND on_demand_price_cents <= $%d", argCount)
			args = append(args, *filter.MaxPriceCents)
			argCount++
		}
	}
	
	query += " ORDER BY family, vcpus, memory_gb"
	
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var types []*InstanceType
	for rows.Next() {
		it := &InstanceType{}
		err := rows.Scan(
			&it.ID, &it.Name, &it.Family, &it.Generation, &it.Size,
			&it.VCPUs, &it.CPUCreditsPerHour, &it.Architecture, &it.ClockSpeedGHz,
			&it.MemoryGB, &it.StorageType, &it.InstanceStorageGB, &it.EBSOptimized, &it.EBSBandwidthMbps,
			&it.NetworkPerformance, &it.MaxNetworkCards, &it.IPv6Supported, &it.ENASupported,
			&it.GPUs, &it.GPUMemoryGB, &it.GPUModel,
			&it.DedicatedHost, &it.Burstable, &it.HibernationSupport,
			&it.OnDemandPrice, &it.SpotBasePrice,
			pq.Array(&it.AvailableRegions), &it.Active, &it.Description,
			&it.CreatedAt, &it.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		types = append(types, it)
	}
	
	return types, rows.Err()
}

// InstanceTypeService provides business logic for instance types
type InstanceTypeService struct {
	repo *InstanceTypeRepository
}

func NewInstanceTypeService(repo *InstanceTypeRepository) *InstanceTypeService {
	return &InstanceTypeService{repo: repo}
}

// ValidateInstanceType checks if an instance type is valid for the given region
func (s *InstanceTypeService) ValidateInstanceType(ctx context.Context, typeName, region string) error {
	it, err := s.repo.GetInstanceType(ctx, typeName)
	if err != nil {
		return fmt.Errorf("invalid instance type: %w", err)
	}
	
	if !it.Active {
		return fmt.Errorf("instance type %s is not active", typeName)
	}
	
	// Check region availability
	regionAvailable := false
	for _, r := range it.AvailableRegions {
		if r == region {
			regionAvailable = true
			break
		}
	}
	
	if !regionAvailable {
		return fmt.Errorf("instance type %s is not available in region %s", typeName, region)
	}
	
	return nil
}

// GetRecommendedInstanceTypes suggests instance types based on requirements
func (s *InstanceTypeService) GetRecommendedInstanceTypes(ctx context.Context, requirements InstanceTypeFilter) ([]*InstanceType, error) {
	types, err := s.repo.ListInstanceTypes(ctx, &requirements)
	if err != nil {
		return nil, err
	}
	
	// Limit to top 10 recommendations
	if len(types) > 10 {
		types = types[:10]
	}
	
	return types, nil
}

// CompareInstanceTypes provides a comparison between instance types
func (s *InstanceTypeService) CompareInstanceTypes(ctx context.Context, typeNames []string) (map[string]*InstanceType, error) {
	comparison := make(map[string]*InstanceType)
	
	for _, name := range typeNames {
		it, err := s.repo.GetInstanceType(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("failed to get instance type %s: %w", name, err)
		}
		comparison[name] = it
	}
	
	return comparison, nil
}

// CalculateHourlyCost calculates the hourly cost based on instance type and pricing model
func (s *InstanceTypeService) CalculateHourlyCost(ctx context.Context, typeName string, spot bool) (int64, error) {
	it, err := s.repo.GetInstanceType(ctx, typeName)
	if err != nil {
		return 0, err
	}
	
	if spot {
		return it.SpotBasePrice, nil
	}
	
	return it.OnDemandPrice, nil
}

// EstimateMonthlyCost estimates monthly cost (730 hours)
func (s *InstanceTypeService) EstimateMonthlyCost(ctx context.Context, typeName string, spot bool) (int64, error) {
	hourlyCost, err := s.CalculateHourlyCost(ctx, typeName, spot)
	if err != nil {
		return 0, err
	}
	
	return hourlyCost * 730, nil
}

// GetInstanceTypesByFamily retrieves all instance types in a family
func (s *InstanceTypeService) GetInstanceTypesByFamily(ctx context.Context, family InstanceFamily) ([]*InstanceType, error) {
	filter := &InstanceTypeFilter{
		Family: &family,
	}
	
	return s.repo.ListInstanceTypes(ctx, filter)
}

// InitializeDefaultInstanceTypes seeds the database with common instance types
func (s *InstanceTypeService) InitializeDefaultInstanceTypes(ctx context.Context) error {
	defaultTypes := []*InstanceType{
		// General Purpose - M5 family
		{
			Name: "m5.large", Family: FamilyGeneralPurpose, Generation: Generation3, Size: "large",
			VCPUs: 2, MemoryGB: 8, Architecture: ArchX86_64, ClockSpeedGHz: 3.1,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 3, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 9600, SpotBasePrice: 2880, // $0.096/hr, ~70% discount for spot
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "General purpose instance with balanced compute, memory, and networking",
		},
		{
			Name: "m5.xlarge", Family: FamilyGeneralPurpose, Generation: Generation3, Size: "xlarge",
			VCPUs: 4, MemoryGB: 16, Architecture: ArchX86_64, ClockSpeedGHz: 3.1,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 4, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 19200, SpotBasePrice: 5760,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "General purpose instance with balanced compute, memory, and networking",
		},
		
		// Compute Optimized - C5 family
		{
			Name: "c5.large", Family: FamilyComputeOptimized, Generation: Generation3, Size: "large",
			VCPUs: 2, MemoryGB: 4, Architecture: ArchX86_64, ClockSpeedGHz: 3.4,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 3, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 8500, SpotBasePrice: 2550,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "Compute optimized instance ideal for compute-bound applications",
		},
		{
			Name: "c5.xlarge", Family: FamilyComputeOptimized, Generation: Generation3, Size: "xlarge",
			VCPUs: 4, MemoryGB: 8, Architecture: ArchX86_64, ClockSpeedGHz: 3.4,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 4, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 17000, SpotBasePrice: 5100,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "Compute optimized instance ideal for compute-bound applications",
		},
		
		// Memory Optimized - R5 family
		{
			Name: "r5.large", Family: FamilyMemoryOptimized, Generation: Generation3, Size: "large",
			VCPUs: 2, MemoryGB: 16, Architecture: ArchX86_64, ClockSpeedGHz: 3.1,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 3, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 12600, SpotBasePrice: 3780,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "Memory optimized instance for memory-intensive applications",
		},
		{
			Name: "r5.xlarge", Family: FamilyMemoryOptimized, Generation: Generation3, Size: "xlarge",
			VCPUs: 4, MemoryGB: 32, Architecture: ArchX86_64, ClockSpeedGHz: 3.1,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 4, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 25200, SpotBasePrice: 7560,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "Memory optimized instance for memory-intensive applications",
		},
		
		// Burstable - T3 family
		{
			Name: "t3.micro", Family: FamilyGeneralPurpose, Generation: Generation3, Size: "micro",
			VCPUs: 2, CPUCreditsPerHour: intPtr(24), MemoryGB: 1, Architecture: ArchX86_64, ClockSpeedGHz: 2.5,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 2085,
			NetworkPerformance: NetworkLow, MaxNetworkCards: 2, IPv6Supported: true, ENASupported: true,
			Burstable: true,
			OnDemandPrice: 1040, SpotBasePrice: 312,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Active: true, Description: "Burstable performance instance for variable workloads",
		},
		
		// GPU Accelerated - P3 family
		{
			Name: "p3.2xlarge", Family: FamilyGPUAccelerated, Generation: Generation3, Size: "2xlarge",
			VCPUs: 8, MemoryGB: 61, Architecture: ArchX86_64, ClockSpeedGHz: 2.7,
			StorageType: StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 10000,
			NetworkPerformance: NetworkHigh, MaxNetworkCards: 4, IPv6Supported: true, ENASupported: true,
			GPUs: 1, GPUMemoryGB: 16, GPUModel: "Tesla V100",
			OnDemandPrice: 306000, SpotBasePrice: 91800,
			AvailableRegions: []string{"us-east-1", "us-west-2"},
			Active: true, Description: "GPU instance for machine learning and HPC workloads",
		},
	}
	
	for _, it := range defaultTypes {
		if err := s.repo.CreateInstanceType(ctx, it); err != nil {
			return fmt.Errorf("failed to create instance type %s: %w", it.Name, err)
		}
	}
	
	return nil
}

func intPtr(i int) *int {
	return &i
}