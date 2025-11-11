# Instance Types and Sizing System

## Overview

The Instance Types and Sizing system is a core component of our cloud service that defines and manages the various compute instance configurations available to users. This system provides a flexible, scalable way to define instance types with different CPU, memory, storage, and network configurations.

## Architecture

### Components

1. **Data Models** (`instance_types.go`)
   - Instance type definitions with complete specifications
   - Filter models for querying
   - Support for multiple instance families

2. **Database Schema** (`schema.sql`)
   - Main instance types table
   - Pricing history tracking
   - Regional configuration overrides
   - Quota management per account

3. **HTTP API** (`api.go`)
   - RESTful endpoints for instance type operations
   - Comprehensive filtering and search
   - Comparison and recommendation features

4. **CLI Tool** (`cli.go`)
   - Command-line interface for management
   - Human-readable output formats
   - Interactive comparison tools

## Instance Families

### General Purpose (M-series)
- **Use Case**: Balanced workloads, web servers, small databases
- **Characteristics**: Balanced CPU, memory, and networking
- **Examples**: m5.large, m5.xlarge, m5.2xlarge

### Compute Optimized (C-series)
- **Use Case**: CPU-intensive applications, batch processing, encoding
- **Characteristics**: High CPU-to-memory ratio, high clock speeds
- **Examples**: c5.large, c5.xlarge, c5.4xlarge

### Memory Optimized (R-series)
- **Use Case**: In-memory databases, caching, big data analytics
- **Characteristics**: High memory-to-CPU ratio
- **Examples**: r5.large, r5.xlarge, r5.4xlarge

### Storage Optimized (I-series)
- **Use Case**: NoSQL databases, data warehousing, log processing
- **Characteristics**: High disk throughput, local NVMe storage
- **Examples**: i3.large, i3.xlarge, i3.4xlarge

### GPU Accelerated (P-series)
- **Use Case**: Machine learning, HPC, graphics rendering
- **Characteristics**: NVIDIA GPUs, high memory, optimized networking
- **Examples**: p3.2xlarge, p3.8xlarge, p3.16xlarge

### Burstable (T-series)
- **Use Case**: Development, testing, variable workloads
- **Characteristics**: CPU credits, burst performance
- **Examples**: t3.micro, t3.small, t3.medium

## Database Schema

### Core Tables

#### instance_types
Main table storing all instance type definitions with specifications.

**Key Fields:**
- Compute: vCPUs, architecture, clock speed, CPU credits
- Memory: RAM in GB
- Storage: Type, capacity, EBS optimization
- Network: Performance tier, max NICs, IPv6/ENA support
- GPU: Count, memory, model
- Pricing: On-demand and spot prices in cents

#### instance_type_pricing_history
Tracks historical price changes for analysis and auditing.

#### instance_type_regional_config
Regional availability and pricing overrides for specific markets.

#### instance_type_quotas
Per-account quotas to manage resource allocation.

### Indexes

Optimized indexes for common query patterns:
- Family, vCPUs, memory filtering
- Price-based searches
- Regional availability lookups
- Composite indexes for multi-criteria filters

## API Endpoints

### List Instance Types
```
GET /instance-types
```

**Query Parameters:**
- `family`: Filter by instance family
- `min_vcpus`, `max_vcpus`: vCPU range
- `min_memory_gb`, `max_memory_gb`: Memory range
- `architecture`: CPU architecture filter
- `region`: Regional availability
- `gpu_required`: Require GPU instances
- `burstable`: Burstable instances only
- `max_price_cents`: Maximum hourly price

**Response:**
```json
[
  {
    "id": "uuid",
    "name": "m5.large",
    "family": "general",
    "vcpus": 2,
    "memory_gb": 8.0,
    "architecture": "x86_64",
    "on_demand_price_cents": 9600,
    "spot_base_price_cents": 2880,
    ...
  }
]
```

### Get Instance Type Details
```
GET /instance-types/{name}
```

Returns complete specifications for a specific instance type.

### Get Recommendations
```
POST /instance-types/recommend
```

**Request Body:**
```json
{
  "min_vcpus": 2,
  "min_memory_gb": 8,
  "max_price_cents": 15000,
  "region": "us-east-1",
  "workload": "web"
}
```

Returns up to 10 recommended instance types based on criteria.

### Compare Instance Types
```
POST /instance-types/compare
```

**Request Body:**
```json
{
  "instance_types": ["m5.large", "c5.xlarge", "r5.large"]
}
```

Returns side-by-side comparison of specified instance types.

### Get Pricing
```
GET /instance-types/{name}/pricing
```

Returns detailed pricing information including hourly and monthly costs for both on-demand and spot instances.

### List by Family
```
GET /instance-types/families/{family}
```

Returns all instance types in a specific family.

## CLI Usage

### Installation
```bash
go install github.com/yourorg/cloud/cmd/instance-types@latest
```

### Commands

#### List Instance Types
```bash
# List all instance types
instance-types list

# Filter by family
instance-types list --family compute

# Filter by specifications
instance-types list --min-vcpus 4 --min-memory 16 --max-price 20000

# Filter by region
instance-types list --region us-west-2

# GPU instances only
instance-types list --gpu
```

#### Describe Instance Type
```bash
instance-types describe m5.large
```

Output:
```
Instance Type: m5.large
═══════════════════════════════════════════════

Family:          general
Generation:      gen3
Size:            large

Compute:
  vCPUs:         2
  Architecture:  x86_64
  Clock Speed:   3.1 GHz

Memory:
  RAM:           8.0 GB

Storage:
  Type:          ebs_only
  EBS Optimized: true
  EBS Bandwidth: 4750 Mbps

Network:
  Performance:   high
  Max NICs:      3
  IPv6:          true
  ENA:           true

Pricing (USD):
  On-Demand:     $0.096/hour  ($70.08/month)
  Spot:          $0.029/hour  ($21.02/month)
  Spot Savings:  70%
```

#### Compare Instance Types
```bash
instance-types compare m5.large c5.xlarge r5.large
```

#### Get Recommendations
```bash
instance-types recommend --min-vcpus 4 --min-memory 16 --max-price 25000
```

#### Show Pricing
```bash
instance-types pricing m5.large
```

Output:
```
Pricing for m5.large (USD)
═══════════════════════════════════════════════

Period   On-Demand   Spot      Savings
------   ---------   ----      -------
Hourly   $0.096      $0.029    70%
Daily    $2.30       $0.69     70%
Monthly  $70.08      $21.02    70%
Yearly   $840.96     $252.29   70%

Monthly savings with Spot: $49.06
Yearly savings with Spot: $588.67
```

## Integration with VM Management

The instance types system integrates with the VM provisioning system:

```go
// Validate instance type before creating VM
err := instanceTypeService.ValidateInstanceType(ctx, "m5.large", "us-east-1")
if err != nil {
    return fmt.Errorf("invalid instance type: %w", err)
}

// Get instance specifications for VM provisioning
instanceType, err := repo.GetInstanceType(ctx, "m5.large")
if err != nil {
    return err
}

// Use specifications to configure VM
vmConfig := &VMConfig{
    VCPUs:    instanceType.VCPUs,
    MemoryMB: int(instanceType.MemoryGB * 1024),
    // ... other configuration
}
```

## Pricing Model

### Price Structure
- Prices stored in cents for precision
- On-demand pricing: base rate
- Spot pricing: typically 60-90% discount
- Regional pricing overrides supported

### Cost Calculation
```go
// Hourly cost
hourlyCost, _ := service.CalculateHourlyCost(ctx, "m5.large", false)

// Monthly estimate (730 hours)
monthlyCost, _ := service.EstimateMonthlyCost(ctx, "m5.large", false)

// Spot vs on-demand comparison
onDemand, _ := service.CalculateHourlyCost(ctx, "m5.large", false)
spot, _ := service.CalculateHourlyCost(ctx, "m5.large", true)
savings := 100.0 * (1.0 - float64(spot)/float64(onDemand))
```

## Workload Recommendations

The system provides intelligent recommendations based on workload types:

### Web/API Servers
- Recommended: General purpose (M-series) or Burstable (T-series)
- Focus: Balanced resources, cost-effectiveness

### Databases
- Recommended: Memory optimized (R-series)
- Focus: High memory, fast storage

### Compute/Batch Processing
- Recommended: Compute optimized (C-series)
- Focus: High CPU performance

### Machine Learning
- Recommended: GPU accelerated (P-series)
- Focus: GPU count, GPU memory, high network throughput

### Storage/Backup
- Recommended: Storage optimized (I-series)
- Focus: Local storage capacity, disk throughput

## Testing

Comprehensive test coverage including:

### Unit Tests
- Repository operations
- Service logic
- Filter combinations
- Price calculations

### Integration Tests
- Database operations
- API endpoints
- Regional availability
- Quota management

### Benchmarks
- Query performance
- Filter efficiency
- Large dataset handling

Run tests:
```bash
go test ./compute/... -v
go test ./compute/... -bench=.
```

## Performance Considerations

### Caching Strategy
- Cache frequently accessed instance types
- Cache regional configurations
- Invalidate on price changes

### Query Optimization
- Use composite indexes for multi-criteria filters
- Leverage PostgreSQL arrays for region filtering
- Implement pagination for large result sets

### Scalability
- Instance types are read-heavy
- Database replication for read scaling
- CDN caching for static instance type data

## Future Enhancements

### Planned Features
1. **Reserved Instances**: Long-term pricing discounts
2. **Savings Plans**: Flexible commitment-based pricing
3. **Instance Recommendations ML**: ML-based workload analysis
4. **Historical Price Analysis**: Spot price trends and predictions
5. **Carbon Footprint**: Environmental impact metrics
6. **ARM Support**: Apple Silicon and Graviton instances
7. **Availability Zones**: AZ-specific configurations
8. **Dedicated Hosts**: Licensing and compliance requirements

### API Extensions
- GraphQL endpoint for complex queries
- WebSocket for real-time spot price updates
- Bulk operations API
- Instance type marketplace (third-party types)

## Best Practices

### For Users
1. Use burstable instances (T-series) for variable workloads
2. Consider spot instances for fault-tolerant workloads
3. Right-size instances based on actual usage
4. Use appropriate instance family for workload
5. Enable auto-scaling to optimize costs

### For Administrators
1. Regularly review and update pricing
2. Monitor quota usage and adjust limits
3. Archive inactive instance types
4. Maintain regional configuration consistency
5. Document instance type deprecation plans

## Troubleshooting

### Common Issues

**Instance type not available in region**
- Verify regional configuration
- Check available_regions array
- Review instance_type_regional_config table

**Quota exceeded**
- Check instance_type_quotas table
- Contact support for quota increase
- Consider alternative instance types

**Pricing discrepancies**
- Check instance_type_pricing_history
- Verify regional price overrides
- Ensure cache invalidation after updates

## Support

For questions or issues:
- Documentation: https://docs.yourcloud.com/instance-types
- Support: support@yourcloud.com
- GitHub: https://github.com/yourorg/cloud/issues