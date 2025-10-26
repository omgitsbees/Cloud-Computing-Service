-- DNS Routing Policy Database Schema

-- Main routing policies table
CREATE TABLE IF NOT EXISTS routing_policies (
    id VARCHAR(255) PRIMARY KEY,
    hosted_zone_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL, -- A, AAAA, CNAME, MX, etc.
    ttl INTEGER NOT NULL DEFAULT 300,
    routing_policy VARCHAR(50) NOT NULL, -- simple, weighted, latency, failover, etc.
    health_check_id VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_hosted_zone FOREIGN KEY (hosted_zone_id) 
        REFERENCES hosted_zones(id) ON DELETE CASCADE,
    CONSTRAINT fk_health_check FOREIGN KEY (health_check_id)
        REFERENCES health_checks(id) ON DELETE SET NULL,
    CONSTRAINT check_routing_policy CHECK (
        routing_policy IN ('simple', 'weighted', 'latency', 'failover', 
                          'geolocation', 'geoproximity', 'multivalue', 'ipbased')
    )
);

-- Record sets for routing policies
CREATE TABLE IF NOT EXISTS routing_policy_record_sets (
    id VARCHAR(255) PRIMARY KEY,
    routing_policy_id VARCHAR(255) NOT NULL,
    values JSONB NOT NULL, -- Array of IP addresses or values
    weight BIGINT DEFAULT 0, -- For weighted routing
    region VARCHAR(50), -- For latency-based routing
    priority INTEGER DEFAULT 0, -- For failover routing
    health_check_id VARCHAR(255),
    geo_location JSONB, -- For geolocation routing
    coordinates JSONB, -- For geoproximity routing
    bias INTEGER DEFAULT 0, -- For geoproximity routing (-99 to 99)
    ip_ranges JSONB, -- For IP-based routing
    set_identifier VARCHAR(255) NOT NULL, -- Unique identifier for this record set
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_routing_policy FOREIGN KEY (routing_policy_id)
        REFERENCES routing_policies(id) ON DELETE CASCADE,
    CONSTRAINT fk_health_check FOREIGN KEY (health_check_id)
        REFERENCES health_checks(id) ON DELETE SET NULL,
    CONSTRAINT check_bias_range CHECK (bias >= -99 AND bias <= 99)
);

-- Latency measurements table
CREATE TABLE IF NOT EXISTS latency_measurements (
    id SERIAL PRIMARY KEY,
    source_region VARCHAR(50) NOT NULL,
    target_region VARCHAR(50) NOT NULL,
    latency_ms BIGINT NOT NULL,
    measured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE (source_region, target_region)
);

-- GeoIP location cache
CREATE TABLE IF NOT EXISTS geoip_cache (
    ip_address INET PRIMARY KEY,
    continent_code VARCHAR(2),
    country_code VARCHAR(2),
    subdivision_code VARCHAR(10),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    cached_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Routing metrics table
CREATE TABLE IF NOT EXISTS routing_metrics (
    id SERIAL PRIMARY KEY,
    routing_policy_id VARCHAR(255) NOT NULL,
    query_count BIGINT NOT NULL DEFAULT 0,
    failover_count BIGINT NOT NULL DEFAULT 0,
    avg_response_time_ms DOUBLE PRECISION,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_routing_policy FOREIGN KEY (routing_policy_id)
        REFERENCES routing_policies(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_routing_policies_hosted_zone ON routing_policies(hosted_zone_id);
CREATE INDEX idx_routing_policies_name_type ON routing_policies(name, type);
CREATE INDEX idx_routing_policies_policy_type ON routing_policies(routing_policy);

CREATE INDEX idx_record_sets_routing_policy ON routing_policy_record_sets(routing_policy_id);
CREATE INDEX idx_record_sets_region ON routing_policy_record_sets(region) WHERE region IS NOT NULL;
CREATE INDEX idx_record_sets_priority ON routing_policy_record_sets(priority);
CREATE INDEX idx_record_sets_set_identifier ON routing_policy_record_sets(set_identifier);

CREATE INDEX idx_latency_source_region ON latency_measurements(source_region);
CREATE INDEX idx_latency_target_region ON latency_measurements(target_region);

CREATE INDEX idx_geoip_expires ON geoip_cache(expires_at);

CREATE INDEX idx_routing_metrics_policy ON routing_metrics(routing_policy_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for routing_policies
CREATE TRIGGER update_routing_policies_updated_at
    BEFORE UPDATE ON routing_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired GeoIP cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_geoip_cache()
RETURNS void AS $$
BEGIN
    DELETE FROM geoip_cache WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- View for routing policy statistics
CREATE OR REPLACE VIEW routing_policy_stats AS
SELECT 
    rp.id,
    rp.name,
    rp.routing_policy,
    COUNT(DISTINCT rprs.id) as record_set_count,
    COUNT(DISTINCT rprs.health_check_id) as health_check_count,
    rm.query_count,
    rm.failover_count,
    rm.avg_response_time_ms,
    rp.created_at,
    rp.updated_at
FROM routing_policies rp
LEFT JOIN routing_policy_record_sets rprs ON rp.id = rprs.routing_policy_id
LEFT JOIN routing_metrics rm ON rp.id = rm.routing_policy_id
GROUP BY rp.id, rp.name, rp.routing_policy, rp.created_at, rp.updated_at,
         rm.query_count, rm.failover_count, rm.avg_response_time_ms;

-- Sample data insertion functions

-- Function to create a simple routing policy
CREATE OR REPLACE FUNCTION create_simple_routing_policy(
    p_hosted_zone_id VARCHAR,
    p_name VARCHAR,
    p_type VARCHAR,
    p_ttl INTEGER,
    p_values TEXT[]
) RETURNS VARCHAR AS $$
DECLARE
    v_policy_id VARCHAR;
    v_record_set_id VARCHAR;
BEGIN
    v_policy_id := 'rp_' || gen_random_uuid()::text;
    
    INSERT INTO routing_policies (id, hosted_zone_id, name, type, ttl, routing_policy)
    VALUES (v_policy_id, p_hosted_zone_id, p_name, p_type, p_ttl, 'simple');
    
    v_record_set_id := 'rs_' || gen_random_uuid()::text;
    
    INSERT INTO routing_policy_record_sets (
        id, routing_policy_id, values, set_identifier
    ) VALUES (
        v_record_set_id, v_policy_id, to_jsonb(p_values), 'default'
    );
    
    RETURN v_policy_id;
END;
$$ LANGUAGE plpgsql;

-- Function to add weighted record set
CREATE OR REPLACE FUNCTION add_weighted_record_set(
    p_routing_policy_id VARCHAR,
    p_values TEXT[],
    p_weight BIGINT,
    p_set_identifier VARCHAR,
    p_health_check_id VARCHAR DEFAULT NULL
) RETURNS VARCHAR AS $$
DECLARE
    v_record_set_id VARCHAR;
BEGIN
    v_record_set_id := 'rs_' || gen_random_uuid()::text;
    
    INSERT INTO routing_policy_record_sets (
        id, routing_policy_id, values, weight, set_identifier, health_check_id
    ) VALUES (
        v_record_set_id, p_routing_policy_id, to_jsonb(p_values), 
        p_weight, p_set_identifier, p_health_check_id
    );
    
    RETURN v_record_set_id;
END;
$$ LANGUAGE plpgsql;

-- Function to add failover record set
CREATE OR REPLACE FUNCTION add_failover_record_set(
    p_routing_policy_id VARCHAR,
    p_values TEXT[],
    p_priority INTEGER,
    p_set_identifier VARCHAR,
    p_health_check_id VARCHAR
) RETURNS VARCHAR AS $$
DECLARE
    v_record_set_id VARCHAR;
BEGIN
    v_record_set_id := 'rs_' || gen_random_uuid()::text;
    
    INSERT INTO routing_policy_record_sets (
        id, routing_policy_id, values, priority, set_identifier, health_check_id
    ) VALUES (
        v_record_set_id, p_routing_policy_id, to_jsonb(p_values),
        p_priority, p_set_identifier, p_health_check_id
    );
    
    RETURN v_record_set_id;
END;
$$ LANGUAGE plpgsql;

-- Function to add geolocation record set
CREATE OR REPLACE FUNCTION add_geolocation_record_set(
    p_routing_policy_id VARCHAR,
    p_values TEXT[],
    p_continent_code VARCHAR DEFAULT NULL,
    p_country_code VARCHAR DEFAULT NULL,
    p_subdivision_code VARCHAR DEFAULT NULL,
    p_set_identifier VARCHAR DEFAULT 'default',
    p_health_check_id VARCHAR DEFAULT NULL
) RETURNS VARCHAR AS $$
DECLARE
    v_record_set_id VARCHAR;
    v_geo_location JSONB;
BEGIN
    v_record_set_id := 'rs_' || gen_random_uuid()::text;
    
    IF p_continent_code IS NOT NULL OR p_country_code IS NOT NULL OR p_subdivision_code IS NOT NULL THEN
        v_geo_location := jsonb_build_object(
            'continent_code', p_continent_code,
            'country_code', p_country_code,
            'subdivision_code', p_subdivision_code
        );
    END IF;
    
    INSERT INTO routing_policy_record_sets (
        id, routing_policy_id, values, geo_location, set_identifier, health_check_id
    ) VALUES (
        v_record_set_id, p_routing_policy_id, to_jsonb(p_values),
        v_geo_location, p_set_identifier, p_health_check_id
    );
    
    RETURN v_record_set_id;
END;
$$ LANGUAGE plpgsql;

-- Function to update latency measurements
CREATE OR REPLACE FUNCTION update_latency_measurement(
    p_source_region VARCHAR,
    p_target_region VARCHAR,
    p_latency_ms BIGINT
) RETURNS void AS $$
BEGIN
    INSERT INTO latency_measurements (source_region, target_region, latency_ms, measured_at)
    VALUES (p_source_region, p_target_region, p_latency_ms, CURRENT_TIMESTAMP)
    ON CONFLICT (source_region, target_region)
    DO UPDATE SET 
        latency_ms = EXCLUDED.latency_ms,
        measured_at = EXCLUDED.measured_at;
END;
$$ LANGUAGE plpgsql;

-- Function to cache GeoIP lookup
CREATE OR REPLACE FUNCTION cache_geoip_lookup(
    p_ip_address INET,
    p_continent_code VARCHAR,
    p_country_code VARCHAR,
    p_subdivision_code VARCHAR,
    p_latitude DOUBLE PRECISION,
    p_longitude DOUBLE PRECISION,
    p_cache_duration_hours INTEGER DEFAULT 24
) RETURNS void AS $$
BEGIN
    INSERT INTO geoip_cache (
        ip_address, continent_code, country_code, subdivision_code,
        latitude, longitude, cached_at, expires_at
    ) VALUES (
        p_ip_address, p_continent_code, p_country_code, p_subdivision_code,
        p_latitude, p_longitude, CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP + (p_cache_duration_hours || ' hours')::INTERVAL
    )
    ON CONFLICT (ip_address)
    DO UPDATE SET
        continent_code = EXCLUDED.continent_code,
        country_code = EXCLUDED.country_code,
        subdivision_code = EXCLUDED.subdivision_code,
        latitude = EXCLUDED.latitude,
        longitude = EXCLUDED.longitude,
        cached_at = EXCLUDED.cached_at,
        expires_at = EXCLUDED.expires_at;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE routing_policies IS 'DNS routing policies for traffic management';
COMMENT ON TABLE routing_policy_record_sets IS 'Record sets associated with routing policies';
COMMENT ON TABLE latency_measurements IS 'Inter-region latency measurements for latency-based routing';
COMMENT ON TABLE geoip_cache IS 'Cached GeoIP lookups to reduce external API calls';
COMMENT ON TABLE routing_metrics IS 'Performance metrics for routing policies';

COMMENT ON COLUMN routing_policies.routing_policy IS 'Type of routing: simple, weighted, latency, failover, geolocation, geoproximity, multivalue, ipbased';
COMMENT ON COLUMN routing_policy_record_sets.weight IS 'Weight for weighted routing (0-255)';
COMMENT ON COLUMN routing_policy_record_sets.priority IS 'Priority for failover routing (0 = highest priority)';
COMMENT ON COLUMN routing_policy_record_sets.bias IS 'Bias for geoproximity routing (-99 to 99, each unit = ~50km)';
COMMENT ON COLUMN routing_policy_record_sets.set_identifier IS 'Unique identifier for this record set within the routing policy';