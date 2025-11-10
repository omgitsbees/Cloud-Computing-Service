package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/yourorg/cloud/compute"
)

var (
	// Global flags
	apiEndpoint string
	region      string

	// Filter flags
	family       string
	minVCPUs     int
	maxVCPUs     int
	minMemoryGB  float64
	maxMemoryGB  float64
	architecture string
	gpuRequired  bool
	burstable    bool
	maxPrice     int64

	rootCmd = &cobra.Command{
		Use:   "instance-types",
		Short: "Manage cloud instance types",
		Long:  `A CLI tool for querying and managing cloud instance types`,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&apiEndpoint, "api", "http://localhost:8080", "API endpoint")
	rootCmd.PersistentFlags().StringVar(&region, "region", "us-east-1", "Region")

	// List command
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List available instance types",
		Long:  `List all available instance types with optional filtering`,
		RunE:  runList,
	}

	listCmd.Flags().StringVar(&family, "family", "", "Instance family (general, compute, memory, storage, gpu)")
	listCmd.Flags().IntVar(&minVCPUs, "min-vcpus", 0, "Minimum vCPUs")
	listCmd.Flags().IntVar(&maxVCPUs, "max-vcpus", 0, "Maximum vCPUs")
	listCmd.Flags().Float64Var(&minMemoryGB, "min-memory", 0, "Minimum memory in GB")
	listCmd.Flags().Float64Var(&maxMemoryGB, "max-memory", 0, "Maximum memory in GB")
	listCmd.Flags().StringVar(&architecture, "arch", "", "CPU architecture (x86_64, arm64)")
	listCmd.Flags().BoolVar(&gpuRequired, "gpu", false, "Require GPU")
	listCmd.Flags().BoolVar(&burstable, "burstable", false, "Burstable instances only")
	listCmd.Flags().Int64Var(&maxPrice, "max-price", 0, "Maximum price in cents per hour")

	rootCmd.AddCommand(listCmd)

	// Describe command
	describeCmd := &cobra.Command{
		Use:   "describe [instance-type]",
		Short: "Describe an instance type",
		Long:  `Show detailed information about a specific instance type`,
		Args:  cobra.ExactArgs(1),
		RunE:  runDescribe,
	}

	rootCmd.AddCommand(describeCmd)

	// Compare command
	compareCmd := &cobra.Command{
		Use:   "compare [instance-types...]",
		Short: "Compare multiple instance types",
		Long:  `Compare multiple instance types side by side`,
		Args:  cobra.MinimumNArgs(2),
		RunE:  runCompare,
	}

	rootCmd.AddCommand(compareCmd)

	// Recommend command
	recommendCmd := &cobra.Command{
		Use:   "recommend",
		Short: "Get instance type recommendations",
		Long:  `Get recommended instance types based on your requirements`,
		RunE:  runRecommend,
	}

	recommendCmd.Flags().IntVar(&minVCPUs, "min-vcpus", 0, "Minimum vCPUs")
	recommendCmd.Flags().Float64Var(&minMemoryGB, "min-memory", 0, "Minimum memory in GB")
	recommendCmd.Flags().Int64Var(&maxPrice, "max-price", 0, "Maximum price in cents per hour")
	recommendCmd.Flags().StringVar(&family, "family", "", "Preferred instance family")
	recommendCmd.Flags().BoolVar(&gpuRequired, "gpu", false, "Require GPU")

	rootCmd.AddCommand(recommendCmd)

	// Pricing command
	pricingCmd := &cobra.Command{
		Use:   "pricing [instance-type]",
		Short: "Show pricing for an instance type",
		Long:  `Display pricing information for a specific instance type`,
		Args:  cobra.ExactArgs(1),
		RunE:  runPricing,
	}

	rootCmd.AddCommand(pricingCmd)

	// Families command
	familiesCmd := &cobra.Command{
		Use:   "families",
		Short: "List instance families",
		Long:  `List all available instance families`,
		RunE:  runFamilies,
	}

	rootCmd.AddCommand(familiesCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Build filter
	filter := &compute.InstanceTypeFilter{}

	if family != "" {
		f := compute.InstanceFamily(family)
		filter.Family = &f
	}

	if minVCPUs > 0 {
		filter.MinVCPUs = &minVCPUs
	}

	if maxVCPUs > 0 {
		filter.MaxVCPUs = &maxVCPUs
	}

	if minMemoryGB > 0 {
		filter.MinMemoryGB = &minMemoryGB
	}

	if maxMemoryGB > 0 {
		filter.MaxMemoryGB = &maxMemoryGB
	}

	if architecture != "" {
		arch := compute.Architecture(architecture)
		filter.Architecture = &arch
	}

	if gpuRequired {
		filter.GPURequired = &gpuRequired
	}

	if burstable {
		filter.Burstable = &burstable
	}

	if maxPrice > 0 {
		filter.MaxPriceCents = &maxPrice
	}

	if region != "" {
		filter.Region = &region
	}

	// In a real implementation, this would call the API
	// For now, we'll simulate with mock data
	types := getMockInstanceTypes(filter)

	// Display results in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tFAMILY\tVCPUs\tMEMORY\tPRICE/HR\tDESCRIPTION")
	fmt.Fprintln(w, "----\t------\t-----\t------\t--------\t-----------")

	for _, it := range types {
		price := float64(it.OnDemandPrice) / 100.0
		fmt.Fprintf(w, "%s\t%s\t%d\t%.1fGB\t$%.3f\t%s\n",
			it.Name, it.Family, it.VCPUs, it.MemoryGB, price, truncate(it.Description, 40))
	}

	w.Flush()
	fmt.Printf("\nFound %d instance types\n", len(types))

	return nil
}

func runDescribe(cmd *cobra.Command, args []string) error {
	typeName := args[0]

	// In a real implementation, this would call the API
	it := getMockInstanceType(typeName)
	if it == nil {
		return fmt.Errorf("instance type not found: %s", typeName)
	}

	// Display detailed information
	fmt.Printf("Instance Type: %s\n", it.Name)
	fmt.Printf("═══════════════════════════════════════════════\n\n")

	fmt.Printf("Family:          %s\n", it.Family)
	fmt.Printf("Generation:      %s\n", it.Generation)
	fmt.Printf("Size:            %s\n\n", it.Size)

	fmt.Printf("Compute:\n")
	fmt.Printf("  vCPUs:         %d\n", it.VCPUs)
	fmt.Printf("  Architecture:  %s\n", it.Architecture)
	fmt.Printf("  Clock Speed:   %.1f GHz\n", it.ClockSpeedGHz)
	if it.Burstable {
		fmt.Printf("  Burstable:     Yes (CPU Credits: %d/hour)\n", *it.CPUCreditsPerHour)
	}
	fmt.Println()

	fmt.Printf("Memory:\n")
	fmt.Printf("  RAM:           %.1f GB\n\n", it.MemoryGB)

	fmt.Printf("Storage:\n")
	fmt.Printf("  Type:          %s\n", it.StorageType)
	if it.InstanceStorageGB > 0 {
		fmt.Printf("  Instance:      %d GB\n", it.InstanceStorageGB)
	}
	fmt.Printf("  EBS Optimized: %v\n", it.EBSOptimized)
	fmt.Printf("  EBS Bandwidth: %d Mbps\n\n", it.EBSBandwidthMbps)

	fmt.Printf("Network:\n")
	fmt.Printf("  Performance:   %s\n", it.NetworkPerformance)
	fmt.Printf("  Max NICs:      %d\n", it.MaxNetworkCards)
	fmt.Printf("  IPv6:          %v\n", it.IPv6Supported)
	fmt.Printf("  ENA:           %v\n\n", it.ENASupported)

	if it.GPUs > 0 {
		fmt.Printf("GPU:\n")
		fmt.Printf("  Count:         %d\n", it.GPUs)
		fmt.Printf("  Memory:        %d GB\n", it.GPUMemoryGB)
		fmt.Printf("  Model:         %s\n\n", it.GPUModel)
	}

	onDemandHourly := float64(it.OnDemandPrice) / 100.0
	onDemandMonthly := onDemandHourly * 730
	spotHourly := float64(it.SpotBasePrice) / 100.0
	spotMonthly := spotHourly * 730
	savings := 100.0 * (1.0 - float64(it.SpotBasePrice)/float64(it.OnDemandPrice))

	fmt.Printf("Pricing (USD):\n")
	fmt.Printf("  On-Demand:     $%.3f/hour  ($%.2f/month)\n", onDemandHourly, onDemandMonthly)
	fmt.Printf("  Spot:          $%.3f/hour  ($%.2f/month)\n", spotHourly, spotMonthly)
	fmt.Printf("  Spot Savings:  %.0f%%\n\n", savings)

	fmt.Printf("Availability:\n")
	fmt.Printf("  Regions:       %v\n\n", it.AvailableRegions)

	if it.Description != "" {
		fmt.Printf("Description:\n")
		fmt.Printf("  %s\n", it.Description)
	}

	return nil
}

func runCompare(cmd *cobra.Command, args []string) error {
	typeNames := args

	// In a real implementation, this would call the API
	types := make([]*compute.InstanceType, 0, len(typeNames))
	for _, name := range typeNames {
		it := getMockInstanceType(name)
		if it == nil {
			return fmt.Errorf("instance type not found: %s", name)
		}
		types = append(types, it)
	}

	// Display comparison table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	// Header
	fmt.Fprintf(w, "Specification")
	for _, it := range types {
		fmt.Fprintf(w, "\t%s", it.Name)
	}
	fmt.Fprintln(w)

	// Separator
	fmt.Fprintf(w, "-------------")
	for range types {
		fmt.Fprintf(w, "\t-------")
	}
	fmt.Fprintln(w)

	// Rows
	printCompareRow(w, "Family", types, func(it *compute.InstanceType) string {
		return string(it.Family)
	})

	printCompareRow(w, "vCPUs", types, func(it *compute.InstanceType) string {
		return fmt.Sprintf("%d", it.VCPUs)
	})

	printCompareRow(w, "Memory", types, func(it *compute.InstanceType) string {
		return fmt.Sprintf("%.1f GB", it.MemoryGB)
	})

	printCompareRow(w, "Architecture", types, func(it *compute.InstanceType) string {
		return string(it.Architecture)
	})

	printCompareRow(w, "Network", types, func(it *compute.InstanceType) string {
		return string(it.NetworkPerformance)
	})

	if anyHasGPU(types) {
		printCompareRow(w, "GPUs", types, func(it *compute.InstanceType) string {
			if it.GPUs > 0 {
				return fmt.Sprintf("%d x %s", it.GPUs, it.GPUModel)
			}
			return "-"
		})
	}

	printCompareRow(w, "On-Demand/hr", types, func(it *compute.InstanceType) string {
		return fmt.Sprintf("$%.3f", float64(it.OnDemandPrice)/100.0)
	})

	printCompareRow(w, "Spot/hr", types, func(it *compute.InstanceType) string {
		return fmt.Sprintf("$%.3f", float64(it.SpotBasePrice)/100.0)
	})

	w.Flush()

	return nil
}

func printCompareRow(w *tabwriter.Writer, label string, types []*compute.InstanceType, fn func(*compute.InstanceType) string) {
	fmt.Fprintf(w, "%s", label)
	for _, it := range types {
		fmt.Fprintf(w, "\t%s", fn(it))
	}
	fmt.Fprintln(w)
}

func anyHasGPU(types []*compute.InstanceType) bool {
	for _, it := range types {
		if it.GPUs > 0 {
			return true
		}
	}
	return false
}

func runRecommend(cmd *cobra.Command, args []string) error {
	// Build filter
	filter := &compute.InstanceTypeFilter{}

	if minVCPUs > 0 {
		filter.MinVCPUs = &minVCPUs
	}

	if minMemoryGB > 0 {
		filter.MinMemoryGB = &minMemoryGB
	}

	if maxPrice > 0 {
		filter.MaxPriceCents = &maxPrice
	}

	if family != "" {
		f := compute.InstanceFamily(family)
		filter.Family = &f
	}

	if gpuRequired {
		filter.GPURequired = &gpuRequired
	}

	if region != "" {
		filter.Region = &region
	}

	// In a real implementation, this would call the API
	types := getMockInstanceTypes(filter)

	if len(types) == 0 {
		fmt.Println("No instance types match your requirements.")
		return nil
	}

	// Limit to top 5 recommendations
	if len(types) > 5 {
		types = types[:5]
	}

	fmt.Println("Recommended Instance Types:")
	fmt.Println("═══════════════════════════════════════════════\n")

	for i, it := range types {
		fmt.Printf("%d. %s (%s)\n", i+1, it.Name, it.Family)
		fmt.Printf("   vCPUs: %d, Memory: %.1f GB\n", it.VCPUs, it.MemoryGB)
		fmt.Printf("   Price: $%.3f/hr ($%.2f/month)\n",
			float64(it.OnDemandPrice)/100.0,
			float64(it.OnDemandPrice)*730/100.0)
		fmt.Printf("   %s\n\n", it.Description)
	}

	return nil
}

func runPricing(cmd *cobra.Command, args []string) error {
	typeName := args[0]

	// In a real implementation, this would call the API
	it := getMockInstanceType(typeName)
	if it == nil {
		return fmt.Errorf("instance type not found: %s", typeName)
	}

	onDemandHourly := float64(it.OnDemandPrice) / 100.0
	onDemandDaily := onDemandHourly * 24
	onDemandMonthly := onDemandHourly * 730
	onDemandYearly := onDemandHourly * 8760

	spotHourly := float64(it.SpotBasePrice) / 100.0
	spotDaily := spotHourly * 24
	spotMonthly := spotHourly * 730
	spotYearly := spotHourly * 8760

	savings := 100.0 * (1.0 - float64(it.SpotBasePrice)/float64(it.OnDemandPrice))

	fmt.Printf("Pricing for %s (USD)\n", it.Name)
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Period\tOn-Demand\tSpot\tSavings")
	fmt.Fprintln(w, "------\t---------\t----\t-------")
	fmt.Fprintf(w, "Hourly\t$%.3f\t$%.3f\t%.0f%%\n", onDemandHourly, spotHourly, savings)
	fmt.Fprintf(w, "Daily\t$%.2f\t$%.2f\t%.0f%%\n", onDemandDaily, spotDaily, savings)
	fmt.Fprintf(w, "Monthly\t$%.2f\t$%.2f\t%.0f%%\n", onDemandMonthly, spotMonthly, savings)
	fmt.Fprintf(w, "Yearly\t$%.2f\t$%.2f\t%.0f%%\n", onDemandYearly, spotYearly, savings)
	w.Flush()

	fmt.Println()
	fmt.Printf("Monthly savings with Spot: $%.2f\n", onDemandMonthly-spotMonthly)
	fmt.Printf("Yearly savings with Spot: $%.2f\n", onDemandYearly-spotYearly)

	return nil
}

func runFamilies(cmd *cobra.Command, args []string) error {
	families := []struct {
		Name        compute.InstanceFamily
		Description string
	}{
		{compute.FamilyGeneralPurpose, "Balanced compute, memory, and networking resources"},
		{compute.FamilyComputeOptimized, "High performance processors for compute-intensive applications"},
		{compute.FamilyMemoryOptimized, "Fast performance for memory-intensive workloads"},
		{compute.FamilyStorageOptimized, "High, sequential read and write access to large data sets"},
		{compute.FamilyGPUAccelerated, "Hardware accelerators for graphics processing and ML workloads"},
		{compute.FamilyFPGAAccelerated, "Field programmable gate arrays for specialized workloads"},
	}

	fmt.Println("Instance Families:")
	fmt.Println("═══════════════════════════════════════════════\n")

	for _, f := range families {
		fmt.Printf("%-20s %s\n", f.Name, f.Description)
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Mock functions for demonstration
func getMockInstanceTypes(filter *compute.InstanceTypeFilter) []*compute.InstanceType {
	// In a real implementation, this would call the API
	// For now, return mock data
	return []*compute.InstanceType{
		{
			Name: "m5.large", Family: compute.FamilyGeneralPurpose, VCPUs: 2, MemoryGB: 8,
			Architecture: compute.ArchX86_64, OnDemandPrice: 9600, SpotBasePrice: 2880,
			Description: "Balanced compute, memory, and networking",
		},
		{
			Name: "c5.xlarge", Family: compute.FamilyComputeOptimized, VCPUs: 4, MemoryGB: 8,
			Architecture: compute.ArchX86_64, OnDemandPrice: 17000, SpotBasePrice: 5100,
			Description: "Compute optimized for CPU-intensive applications",
		},
	}
}

func getMockInstanceType(name string) *compute.InstanceType {
	types := map[string]*compute.InstanceType{
		"m5.large": {
			Name: "m5.large", Family: compute.FamilyGeneralPurpose, Generation: compute.Generation3, Size: "large",
			VCPUs: 2, MemoryGB: 8, Architecture: compute.ArchX86_64, ClockSpeedGHz: 3.1,
			StorageType: compute.StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 4750,
			NetworkPerformance: compute.NetworkHigh, MaxNetworkCards: 3, IPv6Supported: true, ENASupported: true,
			OnDemandPrice: 9600, SpotBasePrice: 2880,
			AvailableRegions: []string{"us-east-1", "us-west-2", "eu-west-1"},
			Description:      "Balanced compute, memory, and networking for general workloads",
		},
		"p3.2xlarge": {
			Name: "p3.2xlarge", Family: compute.FamilyGPUAccelerated, Generation: compute.Generation3, Size: "2xlarge",
			VCPUs: 8, MemoryGB: 61, Architecture: compute.ArchX86_64, ClockSpeedGHz: 2.7,
			StorageType: compute.StorageEBS, EBSOptimized: true, EBSBandwidthMbps: 10000,
			NetworkPerformance: compute.NetworkHigh, MaxNetworkCards: 4, IPv6Supported: true, ENASupported: true,
			GPUs: 1, GPUMemoryGB: 16, GPUModel: "Tesla V100",
			OnDemandPrice: 306000, SpotBasePrice: 91800,
			AvailableRegions: []string{"us-east-1", "us-west-2"},
			Description:      "GPU accelerated for machine learning and HPC workloads",
		},
	}

	return types[name]
}
