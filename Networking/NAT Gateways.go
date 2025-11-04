package gateway

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// GatewayType represents the type of gateway
type GatewayType string

const (
	GatewayTypeInternet GatewayType = "internet"
	GatewayTypeNAT      GatewayType = "nat"
)

// GatewayState represents the operational state
type GatewayState string

const (
	StateAvailable   GatewayState = "available"
	StateAttaching   GatewayState = "attaching"
	StateAttached    GatewayState = "attached"
	StateDetaching   GatewayState = "detaching"
	StateDeleting    GatewayState = "deleting"
	StateDeleted     GatewayState = "deleted"
	StateUnavailable GatewayState = "unavailable"
)

// InternetGateway provides internet connectivity for VPC
type InternetGateway struct {
	ID           string
	VPCID        string
	State        GatewayState
	PublicIP     net.IP
	Tags         map[string]string
	CreatedAt    time.Time
	AttachedAt   *time.Time
	mu           sync.RWMutex
	connections  map[string]*Connection // Track active connections
	statsMu      sync.RWMutex
	stats        GatewayStats
}

// NATGateway provides outbound internet connectivity with IP masquerading
type NATGateway struct {
	ID              string
	VPCID           string
	SubnetID        string
	AllocationID    string // Elastic IP allocation
	PrivateIP       net.IP
	PublicIP        net.IP
	State           GatewayState
	Tags            map[string]string
	CreatedAt       time.Time
	mu              sync.RWMutex
	natTable        map[string]*NATEntry // NAT translation table
	connectionPool  *ConnectionPool
	statsMu         sync.RWMutex
	stats           GatewayStats
}

// Connection represents an active network connection
type Connection struct {
	ID            string
	SourceIP      net.IP
	SourcePort    uint16
	DestIP        net.IP
	DestPort      uint16
	Protocol      string
	NATedIP       net.IP
	NATedPort     uint16
	State         string
	CreatedAt     time.Time
	LastActive    time.Time
	BytesSent     uint64
	BytesReceived uint64
}

// NATEntry represents a NAT translation entry
type NATEntry struct {
	InternalIP   net.IP
	InternalPort uint16
	ExternalIP   net.IP
	ExternalPort uint16
	Protocol     string
	CreatedAt    time.Time
	LastUsed     time.Time
	Timeout      time.Duration
}

// GatewayStats tracks gateway usage statistics
type GatewayStats struct {
	BytesIn          uint64
	BytesOut         uint64
	PacketsIn        uint64
	PacketsOut       uint64
	ActiveConnections int
	TotalConnections uint64
	DroppedPackets   uint64
	LastReset        time.Time
}

// ConnectionPool manages available ports for NAT
type ConnectionPool struct {
	availablePorts map[uint16]bool
	mu             sync.Mutex
	minPort        uint16
	maxPort        uint16
}

// GatewayManager manages all gateways in the system
type GatewayManager struct {
	internetGateways map[string]*InternetGateway
	natGateways      map[string]*NATGateway
	mu               sync.RWMutex
	ipAllocator      *IPAllocator
}

// IPAllocator manages public IP addresses
type IPAllocator struct {
	allocated map[string]net.IP
	pool      []net.IP
	mu        sync.Mutex
}

// NewGatewayManager creates a new gateway manager
func NewGatewayManager() *GatewayManager {
	return &GatewayManager{
		internetGateways: make(map[string]*InternetGateway),
		natGateways:      make(map[string]*NATGateway),
		ipAllocator:      NewIPAllocator(),
	}
}

// NewIPAllocator creates a new IP allocator
func NewIPAllocator() *IPAllocator {
	// Initialize with a pool of public IPs (simulated)
	pool := make([]net.IP, 0)
	for i := 1; i < 255; i++ {
		ip := net.IPv4(203, 0, 113, byte(i)) // Using TEST-NET-3 for demo
		pool = append(pool, ip)
	}
	
	return &IPAllocator{
		allocated: make(map[string]net.IP),
		pool:      pool,
	}
}

// AllocateIP allocates a public IP address
func (a *IPAllocator) AllocateIP() (net.IP, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pool) == 0 {
		return nil, "", fmt.Errorf("no available IP addresses")
	}

	ip := a.pool[0]
	a.pool = a.pool[1:]
	
	allocationID := uuid.New().String()
	a.allocated[allocationID] = ip

	return ip, allocationID, nil
}

// ReleaseIP releases a public IP address
func (a *IPAllocator) ReleaseIP(allocationID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip, exists := a.allocated[allocationID]
	if !exists {
		return fmt.Errorf("allocation ID not found")
	}

	delete(a.allocated, allocationID)
	a.pool = append(a.pool, ip)

	return nil
}

// CreateInternetGateway creates a new internet gateway
func (m *GatewayManager) CreateInternetGateway(tags map[string]string) (*InternetGateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	publicIP, _, err := m.ipAllocator.AllocateIP()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate public IP: %w", err)
	}

	igw := &InternetGateway{
		ID:          fmt.Sprintf("igw-%s", uuid.New().String()[:8]),
		State:       StateAvailable,
		PublicIP:    publicIP,
		Tags:        tags,
		CreatedAt:   time.Now(),
		connections: make(map[string]*Connection),
		stats: GatewayStats{
			LastReset: time.Now(),
		},
	}

	m.internetGateways[igw.ID] = igw
	return igw, nil
}

// AttachInternetGateway attaches an IGW to a VPC
func (m *GatewayManager) AttachInternetGateway(igwID, vpcID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	igw, exists := m.internetGateways[igwID]
	if !exists {
		return fmt.Errorf("internet gateway not found")
	}

	igw.mu.Lock()
	defer igw.mu.Unlock()

	if igw.VPCID != "" {
		return fmt.Errorf("gateway already attached to VPC: %s", igw.VPCID)
	}

	igw.State = StateAttaching
	
	// Simulate attachment process
	go func() {
		time.Sleep(2 * time.Second)
		igw.mu.Lock()
		igw.VPCID = vpcID
		igw.State = StateAttached
		now := time.Now()
		igw.AttachedAt = &now
		igw.mu.Unlock()
	}()

	return nil
}

// DetachInternetGateway detaches an IGW from a VPC
func (m *GatewayManager) DetachInternetGateway(igwID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	igw, exists := m.internetGateways[igwID]
	if !exists {
		return fmt.Errorf("internet gateway not found")
	}

	igw.mu.Lock()
	defer igw.mu.Unlock()

	if igw.VPCID == "" {
		return fmt.Errorf("gateway not attached to any VPC")
	}

	igw.State = StateDetaching
	
	go func() {
		time.Sleep(2 * time.Second)
		igw.mu.Lock()
		igw.VPCID = ""
		igw.State = StateAvailable
		igw.AttachedAt = nil
		igw.mu.Unlock()
	}()

	return nil
}

// CreateNATGateway creates a new NAT gateway
func (m *GatewayManager) CreateNATGateway(vpcID, subnetID string, privateIP net.IP, tags map[string]string) (*NATGateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	publicIP, allocationID, err := m.ipAllocator.AllocateIP()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate public IP: %w", err)
	}

	nat := &NATGateway{
		ID:           fmt.Sprintf("nat-%s", uuid.New().String()[:8]),
		VPCID:        vpcID,
		SubnetID:     subnetID,
		AllocationID: allocationID,
		PrivateIP:    privateIP,
		PublicIP:     publicIP,
		State:        StateAvailable,
		Tags:         tags,
		CreatedAt:    time.Now(),
		natTable:     make(map[string]*NATEntry),
		connectionPool: NewConnectionPool(10000, 65535),
		stats: GatewayStats{
			LastReset: time.Now(),
		},
	}

	m.natGateways[nat.ID] = nat
	
	// Start connection cleanup routine
	go nat.cleanupExpiredEntries(context.Background())

	return nat, nil
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(minPort, maxPort uint16) *ConnectionPool {
	pool := &ConnectionPool{
		availablePorts: make(map[uint16]bool),
		minPort:        minPort,
		maxPort:        maxPort,
	}

	for port := minPort; port <= maxPort; port++ {
		pool.availablePorts[port] = true
	}

	return pool
}

// AllocatePort allocates an available port
func (p *ConnectionPool) AllocatePort() (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for port := range p.availablePorts {
		delete(p.availablePorts, port)
		return port, nil
	}

	return 0, fmt.Errorf("no available ports")
}

// ReleasePort releases a port back to the pool
func (p *ConnectionPool) ReleasePort(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.availablePorts[port] = true
}

// TranslateOutbound performs outbound NAT translation
func (nat *NATGateway) TranslateOutbound(srcIP net.IP, srcPort uint16, protocol string) (*NATEntry, error) {
	nat.mu.Lock()
	defer nat.mu.Unlock()

	// Check if translation already exists
	key := fmt.Sprintf("%s:%d:%s", srcIP.String(), srcPort, protocol)
	if entry, exists := nat.natTable[key]; exists {
		entry.LastUsed = time.Now()
		return entry, nil
	}

	// Allocate new external port
	extPort, err := nat.connectionPool.AllocatePort()
	if err != nil {
		return nil, err
	}

	entry := &NATEntry{
		InternalIP:   srcIP,
		InternalPort: srcPort,
		ExternalIP:   nat.PublicIP,
		ExternalPort: extPort,
		Protocol:     protocol,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		Timeout:      5 * time.Minute,
	}

	nat.natTable[key] = entry
	
	// Track statistics
	nat.statsMu.Lock()
	nat.stats.TotalConnections++
	nat.stats.ActiveConnections++
	nat.statsMu.Unlock()

	return entry, nil
}

// TranslateInbound performs inbound NAT translation (reverse lookup)
func (nat *NATGateway) TranslateInbound(extPort uint16, protocol string) (*NATEntry, error) {
	nat.mu.RLock()
	defer nat.mu.RUnlock()

	for _, entry := range nat.natTable {
		if entry.ExternalPort == extPort && entry.Protocol == protocol {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("no NAT entry found for port %d", extPort)
}

// cleanupExpiredEntries removes expired NAT entries
func (nat *NATGateway) cleanupExpiredEntries(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nat.mu.Lock()
			now := time.Now()
			for key, entry := range nat.natTable {
				if now.Sub(entry.LastUsed) > entry.Timeout {
					nat.connectionPool.ReleasePort(entry.ExternalPort)
					delete(nat.natTable, key)
					
					nat.statsMu.Lock()
					nat.stats.ActiveConnections--
					nat.statsMu.Unlock()
				}
			}
			nat.mu.Unlock()
		}
	}
}

// RoutePacket routes a packet through the internet gateway
func (igw *InternetGateway) RoutePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol string, payload []byte) error {
	igw.mu.Lock()
	defer igw.mu.Unlock()

	if igw.State != StateAttached {
		return fmt.Errorf("gateway not attached to VPC")
	}

	// Create or update connection tracking
	connKey := fmt.Sprintf("%s:%d->%s:%d:%s", srcIP, srcPort, dstIP, dstPort, protocol)
	
	conn, exists := igw.connections[connKey]
	if !exists {
		conn = &Connection{
			ID:         uuid.New().String(),
			SourceIP:   srcIP,
			SourcePort: srcPort,
			DestIP:     dstIP,
			DestPort:   dstPort,
			Protocol:   protocol,
			State:      "established",
			CreatedAt:  time.Now(),
			LastActive: time.Now(),
		}
		igw.connections[connKey] = conn
	}

	conn.LastActive = time.Now()
	conn.BytesSent += uint64(len(payload))

	// Update statistics
	igw.statsMu.Lock()
	igw.stats.BytesOut += uint64(len(payload))
	igw.stats.PacketsOut++
	igw.statsMu.Unlock()

	return nil
}

// GetStats returns gateway statistics
func (igw *InternetGateway) GetStats() GatewayStats {
	igw.statsMu.RLock()
	defer igw.statsMu.RUnlock()
	
	igw.mu.RLock()
	igw.stats.ActiveConnections = len(igw.connections)
	igw.mu.RUnlock()
	
	return igw.stats
}

// GetNATStats returns NAT gateway statistics
func (nat *NATGateway) GetStats() GatewayStats {
	nat.statsMu.RLock()
	defer nat.statsMu.RUnlock()
	return nat.stats
}

// DeleteNATGateway deletes a NAT gateway
func (m *GatewayManager) DeleteNATGateway(natID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nat, exists := m.natGateways[natID]
	if !exists {
		return fmt.Errorf("NAT gateway not found")
	}

	// Release the public IP
	if err := m.ipAllocator.ReleaseIP(nat.AllocationID); err != nil {
		return fmt.Errorf("failed to release IP: %w", err)
	}

	delete(m.natGateways, natID)
	return nil
}

// DeleteInternetGateway deletes an internet gateway
func (m *GatewayManager) DeleteInternetGateway(igwID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	igw, exists := m.internetGateways[igwID]
	if !exists {
		return fmt.Errorf("internet gateway not found")
	}

	if igw.VPCID != "" {
		return fmt.Errorf("gateway is still attached to VPC")
	}

	delete(m.internetGateways, igwID)
	return nil
}

// ListInternetGateways returns all internet gateways
func (m *GatewayManager) ListInternetGateways() []*InternetGateway {
	m.mu.RLock()
	defer m.mu.RUnlock()

	gateways := make([]*InternetGateway, 0, len(m.internetGateways))
	for _, igw := range m.internetGateways {
		gateways = append(gateways, igw)
	}
	return gateways
}

// ListNATGateways returns all NAT gateways
func (m *GatewayManager) ListNATGateways() []*NATGateway {
	m.mu.RLock()
	defer m.mu.RUnlock()

	gateways := make([]*NATGateway, 0, len(m.natGateways))
	for _, nat := range m.natGateways {
		gateways = append(gateways, nat)
	}
	return gateways
}