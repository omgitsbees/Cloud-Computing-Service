-- Instance Types Schema
-- This schema stores all available instance type definitions

CREATE TABLE IF NOT EXISTS instance_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL, -- e.g., m5.large
    
    -- Classification
    family VARCHAR(20) NOT NULL, -- general, compute, memory, storage, gpu, fpga
    generation VARCHAR(10) NOT NULL, -- gen1, gen2, gen3
    size VARCHAR(20) NOT NULL, -- nano, micro, small, medium, large, xlarge, 2xlarge, etc.
    
    -- Compute specifications
    vcpus INTEGER NOT NULL,
    cpu_credits_per_hour INTEGER, -- For burstable instances (T-series)
    architecture VARCHAR(10) NOT NULL, -- x86_64, arm64
    clock_speed_ghz DECIMAL(3,2) NOT NULL,
    
    -- Memory specifications
    memory_gb DECIMAL(10,2) NOT NULL,
    
    -- Storage specifications
    storage_type VARCHAR(20) NOT NULL, -- ebs_only, nvme_ssd, hdd
    instance_storage_gb INTEGER DEFAULT 0,
    ebs_optimized BOOLEAN DEFAULT false,
    ebs_bandwidth_mbps INTEGER NOT NULL,
    
    -- Network specifications
    network_performance VARCHAR(20) NOT NULL, -- low, moderate, high, very_high, 10_gbps, etc.
    max_network_cards INTEGER NOT NULL,
    ipv6_supported BOOLEAN DEFAULT true,
    ena_supported BOOLEAN DEFAULT true, -- Enhanced Networking Adapter
    
    -- GPU specifications (nullable for non-GPU instances)
    gpus INTEGER DEFAULT 0,
    gpu_memory_gb INTEGER DEFAULT 0,
    gpu_model VARCHAR(100),
    
    -- Additional features
    dedicated_host_supported BOOLEAN DEFAULT false,
    burstable BOOLEAN DEFAULT false,
    hibernation_support BOOLEAN DEFAULT false,
    
    -- Pricing (stored in cents for precision)
    on_demand_price_cents BIGINT NOT NULL,
    spot_base_price_cents BIGINT NOT NULL,
    
    -- Availability
    available_regions TEXT[] NOT NULL, -- Array of region codes
    active BOOLEAN DEFAULT true,
    
    -- Metadata
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient querying
CREATE INDEX idx_instance_types_family ON instance_types(family);
CREATE INDEX idx_instance_types_vcpus ON instance_types(vcpus);
CREATE INDEX idx_instance_types_memory ON instance_types(memory_gb);
CREATE INDEX idx_instance_types_price ON instance_types(on_demand_price_cents);
CREATE INDEX idx_instance_types_active ON instance_types(active);
CREATE INDEX idx_instance_types_regions ON instance_types USING GIN(available_regions);

-- Create a composite index for common filter combinations
CREATE INDEX idx_instance_types_filter ON instance_types(family, vcpus, memory_gb) 
    WHERE active = true;

-- Instance type pricing history (for tracking price changes over time)
CREATE TABLE IF NOT EXISTS instance_type_pricing_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_type_id UUID NOT NULL REFERENCES instance_types(id) ON DELETE CASCADE,
    on_demand_price_cents BIGINT NOT NULL,
    spot_base_price_cents BIGINT NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pricing_history_instance_type ON instance_type_pricing_history(instance_type_id);
CREATE INDEX idx_pricing_history_valid_range ON instance_type_pricing_history(valid_from, valid_to);

-- Regional availability and pricing overrides
CREATE TABLE IF NOT EXISTS instance_type_regional_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_type_id UUID NOT NULL REFERENCES instance_types(id) ON DELETE CASCADE,
    region_code VARCHAR(50) NOT NULL,
    available BOOLEAN DEFAULT true,
    on_demand_price_cents BIGINT, -- Override base price if set
    spot_base_price_cents BIGINT, -- Override base price if set
    max_instances_per_account INTEGER, -- Regional quotas
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(instance_type_id, region_code)
);

CREATE INDEX idx_regional_config_instance_type ON instance_type_regional_config(instance_type_id);
CREATE INDEX idx_regional_config_region ON instance_type_regional_config(region_code);

-- Instance type quotas per account
CREATE TABLE IF NOT EXISTS instance_type_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL, -- References accounts table
    instance_type_id UUID NOT NULL REFERENCES instance_types(id) ON DELETE CASCADE,
    region_code VARCHAR(50) NOT NULL,
    max_instances INTEGER NOT NULL DEFAULT 20,
    current_usage INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(account_id, instance_type_id, region_code)
);

CREATE INDEX idx_quotas_account ON instance_type_quotas(account_id);
CREATE INDEX idx_quotas_instance_type ON instance_type_quotas(instance_type_id);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_instance_types_updated_at 
    BEFORE UPDATE ON instance_types
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_regional_config_updated_at 
    BEFORE UPDATE ON instance_type_regional_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_quotas_updated_at 
    BEFORE UPDATE ON instance_type_quotas
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- View for easy querying of instance types with regional pricing
CREATE OR REPLACE VIEW instance_types_with_regional_pricing AS
SELECT 
    it.id,
    it.name,
    it.family,
    it.generation,
    it.size,
    it.vcpus,
    it.memory_gb,
    it.architecture,
    it.storage_type,
    it.network_performance,
    it.gpus,
    it.burstable,
    irc.region_code,
    COALESCE(irc.on_demand_price_cents, it.on_demand_price_cents) as region_on_demand_price_cents,
    COALESCE(irc.spot_base_price_cents, it.spot_base_price_cents) as region_spot_price_cents,
    irc.available as region_available,
    it.active,
    it.description
FROM instance_types it
CROSS JOIN UNNEST(it.available_regions) as region_code
LEFT JOIN instance_type_regional_config irc 
    ON it.id = irc.instance_type_id 
    AND irc.region_code = region_code
WHERE it.active = true;

-- Function to get recommended instance types based on requirements
CREATE OR REPLACE FUNCTION get_recommended_instance_types(
    p_min_vcpus INTEGER DEFAULT NULL,
    p_min_memory_gb DECIMAL DEFAULT NULL,
    p_max_price_cents BIGINT DEFAULT NULL,
    p_region VARCHAR DEFAULT NULL,
    p_family VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    name VARCHAR,
    family VARCHAR,
    vcpus INTEGER,
    memory_gb DECIMAL,
    on_demand_price_cents BIGINT,
    description TEXT,
    score DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        it.name,
        it.family::VARCHAR,
        it.vcpus,
        it.memory_gb,
        it.on_demand_price_cents,
        it.description,
        -- Simple scoring: balance between specs and price
        (it.vcpus::DECIMAL + it.memory_gb) / (it.on_demand_price_cents::DECIMAL / 100) as score
    FROM instance_types it
    WHERE it.active = true
        AND (p_min_vcpus IS NULL OR it.vcpus >= p_min_vcpus)
        AND (p_min_memory_gb IS NULL OR it.memory_gb >= p_min_memory_gb)
        AND (p_max_price_cents IS NULL OR it.on_demand_price_cents <= p_max_price_cents)
        AND (p_region IS NULL OR p_region = ANY(it.available_regions))
        AND (p_family IS NULL OR it.family = p_family)
    ORDER BY score DESC
    LIMIT 10;
END;
$$ LANGUAGE plpgsql;

-- Sample data insertion
INSERT INTO instance_types (
    name, family, generation, size,
    vcpus, architecture, clock_speed_ghz, memory_gb,
    storage_type, ebs_optimized, ebs_bandwidth_mbps,
    network_performance, max_network_cards, ipv6_supported, ena_supported,
    on_demand_price_cents, spot_base_price_cents,
    available_regions, description
) VALUES 
    ('t3.micro', 'general', 'gen3', 'micro',
     2, 'x86_64', 2.5, 1.0,
     'ebs_only', true, 2085,
     'low', 2, true, true,
     1040, 312,
     ARRAY['us-east-1', 'us-west-2', 'eu-west-1'],
     'Burstable performance instance ideal for development and testing'),
    
    ('m5.large', 'general', 'gen3', 'large',
     2, 'x86_64', 3.1, 8.0,
     'ebs_only', true, 4750,
     'high', 3, true, true,
     9600, 2880,
     ARRAY['us-east-1', 'us-west-2', 'eu-west-1'],
     'Balanced compute, memory, and networking for general workloads'),
    
    ('c5.xlarge', 'compute', 'gen3', 'xlarge',
     4, 'x86_64', 3.4, 8.0,
     'ebs_only', true, 4750,
     'high', 4, true, true,
     17000, 5100,
     ARRAY['us-east-1', 'us-west-2', 'eu-west-1'],
     'Compute optimized for CPU-intensive applications'),
    
    ('r5.large', 'memory', 'gen3', 'large',
     2, 'x86_64', 3.1, 16.0,
     'ebs_only', true, 4750,
     'high', 3, true, true,
     12600, 3780,
     ARRAY['us-east-1', 'us-west-2', 'eu-west-1'],
     'Memory optimized for in-memory databases and caches'),
    
    ('p3.2xlarge', 'gpu', 'gen3', '2xlarge',
     8, 'x86_64', 2.7, 61.0,
     'ebs_only', true, 10000,
     'high', 4, true, true,
     306000, 91800,
     ARRAY['us-east-1', 'us-west-2'],
     'GPU accelerated for machine learning and HPC workloads')
ON CONFLICT (name) DO NOTHING;