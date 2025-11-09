package compute_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/cloud/compute"
)

// MockInstanceTypeRepository for testing
type MockInstanceTypeRepository struct {
	types map[string]*compute.InstanceType
}

func NewMockInstanceTypeRepository() *MockInstanceTypeRepository {
	return &MockInstanceTypeRepository{
		types: make(map[string]*compute.InstanceType),
	}
}

func (m *MockInstanceTypeRepository) CreateInstanceType(ctx context.Context, it *compute.InstanceType) error {
	m.types[it.Name] = it
	return nil
}

func (m *MockInstanceTypeRepository) GetInstanceType(ctx context.Context, name string) (*compute.InstanceType, error) {
	it, ok := m.types[name]
	if !ok {
		return nil, compute.ErrInstanceTypeNotFound
	}
	return it, nil
}

func (m *MockInstanceTypeRepository) ListInstanceTypes(ctx context.Context, filter *compute.InstanceTypeFilter) ([]*compute.InstanceType, error) {
	var result []*compute.InstanceType

	for _, it := range m.types {
		if matchesFilter(it, filter) {
			result = append(result, it)
		}
	}

	return result, nil
}

func matchesFilter(it *compute.InstanceType, filter *compute.InstanceTypeFilter) bool {
	if filter == nil {
		return true
	}

	if filter.Family != nil && it.Family != *filter.Family {
		return false
	}

	if filter.MinVCPUs != nil && it.VCPUs < *filter.MinVCPUs {
		return false
	}

	if filter.MaxVCPUs != nil && it.VCPUs > *filter.MaxVCPUs {
		return false
	}

	if filter.MinMemoryGB != nil && it.MemoryGB < *filter.MinMemoryGB {
		return false
	}

	if filter.MaxMemoryGB != nil && it.MemoryGB > *filter.MaxMemoryGB {
		return false
	}

	if filter.Architecture != nil && it.Architecture != *filter.Architecture {
		return false
	}

	if filter.Region != nil {
		regionFound := false
		for _, r := range it.AvailableRegions {
			if r == *filter.Region {
				regionFound = true
				break
			}
		}
		if !regionFound {
			return false
		}
	}

	if filter.GPURequired != nil && *filter.GPURequired && it.GPUs == 0 {
		return false
	}

	if filter.Burstable != nil && it.Burstable != *filter.Burstable {
		return false
	}

	if filter.MaxPriceCents != nil && it.OnDemandPrice > *filter.MaxPriceCents {
		return false
	}

	return true
}

func setupTestService() *compute.InstanceTypeService {
	repo := NewMockInstanceTypeRepository()
	service := compute.NewInstanceTypeService(repo)

	// Add test data
	ctx := context.Background()
	testTypes := []*compute.InstanceType{
		{
			Name: "m5.large", Family: compute.FamilyGeneralPurpose, VCPUs: 2, MemoryGB: 8,
			Architecture: compute.ArchX86_64, OnDemandPrice: 9600, SpotBasePrice: 2880,
			AvailableRegions: []string{"us-east-1", "us-west-2"}, Active: true,
		},
		{
			Name: "c5.xlarge", Family: compute.FamilyComputeOptimized, VCPUs: 4, MemoryGB: 8,
			Architecture: compute.ArchX86_64, OnDemandPrice: 17000, SpotBasePrice: 5100,
			AvailableRegions: []string{"us-east-1", "us-west-2"}, Active: true,
		},
		{
			Name: "r5.large", Family: compute.FamilyMemoryOptimized, VCPUs: 2, MemoryGB: 16,
			Architecture: compute.ArchX86_64, OnDemandPrice: 12600, SpotBasePrice: 3780,
			AvailableRegions: []string{"us-east-1"}, Active: true,
		},
		{
			Name: "p3.2xlarge", Family: compute.FamilyGPUAccelerated, VCPUs: 8, MemoryGB: 61,
			Architecture: compute.ArchX86_64, GPUs: 1, OnDemandPrice: 306000, SpotBasePrice: 91800,
			AvailableRegions: []string{"us-east-1"}, Active: true,
		},
		{
			Name: "t3.micro", Family: compute.FamilyGeneralPurpose, VCPUs: 2, MemoryGB: 1,
			Architecture: compute.ArchX86_64, Burstable: true, OnDemandPrice: 1040, SpotBasePrice: 312,
			AvailableRegions: []string{"us-east-1", "us-west-2"}, Active: true,
		},
	}

	for _, it := range testTypes {
		repo.CreateInstanceType(ctx, it)
	}

	return service
}

func TestGetInstanceType(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	t.Run("ExistingInstanceType", func(t *testing.T) {
		it, err := service.repo.GetInstanceType(ctx, "m5.large")
		require.NoError(t, err)
		assert.Equal(t, "m5.large", it.Name)
		assert.Equal(t, 2, it.VCPUs)
		assert.Equal(t, 8.0, it.MemoryGB)
	})

	t.Run("NonExistentInstanceType", func(t *testing.T) {
		_, err := service.repo.GetInstanceType(ctx, "invalid.type")
		assert.Error(t, err)
	})
}

func TestValidateInstanceType(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	t.Run("ValidInstanceTypeInRegion", func(t *testing.T) {
		err := service.ValidateInstanceType(ctx, "m5.large", "us-east-1")
		assert.NoError(t, err)
	})

	t.Run("ValidInstanceTypeNotInRegion", func(t *testing.T) {
		err := service.ValidateInstanceType(ctx, "r5.large", "us-west-2")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not available in region")
	})

	t.Run("InvalidInstanceType", func(t *testing.T) {
		err := service.ValidateInstanceType(ctx, "invalid.type", "us-east-1")
		assert.Error(t, err)
	})
}

func TestFilterByFamily(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	family := compute.FamilyComputeOptimized
	filter := &compute.InstanceTypeFilter{
		Family: &family,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, types, 1)
	assert.Equal(t, "c5.xlarge", types[0].Name)
}

func TestFilterByVCPUs(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	minVCPUs := 4
	filter := &compute.InstanceTypeFilter{
		MinVCPUs: &minVCPUs,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		assert.GreaterOrEqual(t, it.VCPUs, 4)
	}
}

func TestFilterByMemory(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	minMemory := 10.0
	filter := &compute.InstanceTypeFilter{
		MinMemoryGB: &minMemory,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		assert.GreaterOrEqual(t, it.MemoryGB, 10.0)
	}
}

func TestFilterByRegion(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	region := "us-west-2"
	filter := &compute.InstanceTypeFilter{
		Region: &region,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		found := false
		for _, r := range it.AvailableRegions {
			if r == region {
				found = true
				break
			}
		}
		assert.True(t, found, "instance type %s should be available in %s", it.Name, region)
	}
}

func TestFilterByGPU(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	gpuRequired := true
	filter := &compute.InstanceTypeFilter{
		GPURequired: &gpuRequired,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		assert.Greater(t, it.GPUs, 0, "instance type %s should have GPUs", it.Name)
	}
}

func TestFilterByBurstable(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	burstable := true
	filter := &compute.InstanceTypeFilter{
		Burstable: &burstable,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		assert.True(t, it.Burstable, "instance type %s should be burstable", it.Name)
	}
}

func TestFilterByMaxPrice(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	maxPrice := int64(10000)
	filter := &compute.InstanceTypeFilter{
		MaxPriceCents: &maxPrice,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		assert.LessOrEqual(t, it.OnDemandPrice, maxPrice)
	}
}

func TestCombinedFilters(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	minVCPUs := 2
	minMemory := 8.0
	region := "us-east-1"

	filter := &compute.InstanceTypeFilter{
		MinVCPUs:    &minVCPUs,
		MinMemoryGB: &minMemory,
		Region:      &region,
	}

	types, err := service.repo.ListInstanceTypes(ctx, filter)
	require.NoError(t, err)

	for _, it := range types {
		assert.GreaterOrEqual(t, it.VCPUs, 2)
		assert.GreaterOrEqual(t, it.MemoryGB, 8.0)

		found := false
		for _, r := range it.AvailableRegions {
			if r == region {
				found = true
				break
			}
		}
		assert.True(t, found)
	}
}

func TestCompareInstanceTypes(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	typeNames := []string{"m5.large", "c5.xlarge", "r5.large"}
	comparison, err := service.CompareInstanceTypes(ctx, typeNames)

	require.NoError(t, err)
	assert.Len(t, comparison, 3)

	assert.Contains(t, comparison, "m5.large")
	assert.Contains(t, comparison, "c5.xlarge")
	assert.Contains(t, comparison, "r5.large")
}

func TestCalculateCosts(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	t.Run("OnDemandHourlyCost", func(t *testing.T) {
		cost, err := service.CalculateHourlyCost(ctx, "m5.large", false)
		require.NoError(t, err)
		assert.Equal(t, int64(9600), cost)
	})

	t.Run("SpotHourlyCost", func(t *testing.T) {
		cost, err := service.CalculateHourlyCost(ctx, "m5.large", true)
		require.NoError(t, err)
		assert.Equal(t, int64(2880), cost)
	})

	t.Run("MonthlyCost", func(t *testing.T) {
		cost, err := service.EstimateMonthlyCost(ctx, "m5.large", false)
		require.NoError(t, err)
		assert.Equal(t, int64(9600*730), cost) // 730 hours per month
	})
}

func TestGetInstanceTypesByFamily(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	t.Run("GeneralPurpose", func(t *testing.T) {
		types, err := service.GetInstanceTypesByFamily(ctx, compute.FamilyGeneralPurpose)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(types), 2) // m5.large and t3.micro
	})

	t.Run("ComputeOptimized", func(t *testing.T) {
		types, err := service.GetInstanceTypesByFamily(ctx, compute.FamilyComputeOptimized)
		require.NoError(t, err)
		assert.Len(t, types, 1)
		assert.Equal(t, "c5.xlarge", types[0].Name)
	})
}

func TestGetRecommendedInstanceTypes(t *testing.T) {
	service := setupTestService()
	ctx := context.Background()

	t.Run("BasicRecommendation", func(t *testing.T) {
		minVCPUs := 2
		filter := compute.InstanceTypeFilter{
			MinVCPUs: &minVCPUs,
		}

		types, err := service.GetRecommendedInstanceTypes(ctx, filter)
		require.NoError(t, err)
		assert.NotEmpty(t, types)
		assert.LessOrEqual(t, len(types), 10) // Should limit to top 10
	})

	t.Run("NoMatches", func(t *testing.T) {
		minVCPUs := 100
		filter := compute.InstanceTypeFilter{
			MinVCPUs: &minVCPUs,
		}

		types, err := service.GetRecommendedInstanceTypes(ctx, filter)
		require.NoError(t, err)
		assert.Empty(t, types)
	})
}

// Benchmark tests
func BenchmarkGetInstanceType(b *testing.B) {
	service := setupTestService()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.repo.GetInstanceType(ctx, "m5.large")
	}
}

func BenchmarkListInstanceTypes(b *testing.B) {
	service := setupTestService()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.repo.ListInstanceTypes(ctx, nil)
	}
}

func BenchmarkFilterInstanceTypes(b *testing.B) {
	service := setupTestService()
	ctx := context.Background()

	minVCPUs := 2
	minMemory := 8.0
	filter := &compute.InstanceTypeFilter{
		MinVCPUs:    &minVCPUs,
		MinMemoryGB: &minMemory,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.repo.ListInstanceTypes(ctx, filter)
	}
}
