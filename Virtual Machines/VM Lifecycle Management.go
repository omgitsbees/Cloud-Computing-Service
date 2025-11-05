package ec2

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// InstanceState represents the state of an EC2 instance
type InstanceState string

const (
	StatePending      InstanceState = "pending"
	StateRunning      InstanceState = "running"
	StateStopping     InstanceState = "stopping"
	StateStopped      InstanceState = "stopped"
	StateShuttingDown InstanceState = "shutting-down"
	StateTerminated   InstanceState = "terminated"
	StateRebooting    InstanceState = "rebooting"
)

// InstanceType defines the compute capacity
type InstanceType struct {
	Name         string
	VCPUs        int
	MemoryMB     int
	StorageGB    int
	NetworkMbps  int
	PricePerHour float64
}

// Instance represents an EC2 instance
type Instance struct {
	ID                 string
	Name               string
	InstanceType       string
	ImageID            string
	State              InstanceState
	StateReason        string
	VPCID              string
	SubnetID           string
	PrivateIP          string
	PublicIP           string
	SecurityGroups     []string
	KeyName            string
	IAMRole            string
	UserData           string
	Tags               map[string]string
	LaunchTime         time.Time
	StateTransitionTime time.Time
	Monitoring         bool
	EBSOptimized       bool
	TerminationProtection bool
	
	// Resource tracking
	CPU                CpuMetrics
	Memory             MemoryMetrics
	Network            NetworkMetrics
	Disk               DiskMetrics
	
	// Volumes attached
	BlockDevices       []*BlockDeviceMapping
	
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
}

// BlockDeviceMapping represents attached storage
type BlockDeviceMapping struct {
	DeviceName  string
	VolumeID    string
	VolumeSize  int
	VolumeType  string
	DeleteOnTermination bool
	Encrypted   bool
}

// CpuMetrics tracks CPU usage
type CpuMetrics struct {
	UtilizationPercent float64
	CreditBalance      float64
	mu                 sync.RWMutex
}

// MemoryMetrics tracks memory usage
type MemoryMetrics struct {
	UsedMB      int
	AvailableMB int
	mu          sync.RWMutex
}

// NetworkMetrics tracks network usage
type NetworkMetrics struct {
	BytesIn  uint64
	BytesOut uint64
	PacketsIn uint64
	PacketsOut uint64
	mu        sync.RWMutex
}

// DiskMetrics tracks disk I/O
type DiskMetrics struct {
	ReadBytes  uint64
	WriteBytes uint64
	ReadOps    uint64
	WriteOps   uint64
	mu         sync.RWMutex
}

// InstanceManager manages EC2 instances
type InstanceManager struct {
	instances      map[string]*Instance
	instanceTypes  map[string]*InstanceType
	images         map[string]*AMI
	mu             sync.RWMutex
	ipAllocator    *IPAllocator
	volumeManager  *VolumeManager
	scheduler      *InstanceScheduler
}

// AMI represents an Amazon Machine Image
type AMI struct {
	ID           string
	Name         string
	Description  string
	Platform     string
	Architecture string
	RootDevice   string
	CreatedAt    time.Time
	Public       bool
	OwnerID      string
}

// IPAllocator manages IP address allocation
type IPAllocator struct {
	privateIPPool map[string][]string // subnet -> available IPs
	publicIPPool  []string
	allocated     map[string]string // instance ID -> public IP
	mu            sync.Mutex
}

// VolumeManager manages EBS volumes
type VolumeManager struct {
	volumes map[string]*Volume
	mu      sync.RWMutex
}

// Volume represents an EBS volume
type Volume struct {
	ID          string
	Size        int
	VolumeType  string
	IOPS        int
	Encrypted   bool
	State       string
	AttachedTo  string
	Device      string
	CreatedAt   time.Time
}

// InstanceScheduler handles instance lifecycle operations
type InstanceScheduler struct {
	operations chan *InstanceOperation
	mu         sync.RWMutex
}

// InstanceOperation represents a pending operation
type InstanceOperation struct {
	InstanceID string
	Operation  string
	CompletedAt time.Time
	Error      error
}

// LaunchInstanceRequest contains parameters for launching an instance
type LaunchInstanceRequest struct {
	ImageID            string
	InstanceType       string
	KeyName            string
	SecurityGroups     []string
	SubnetID           string
	UserData           string
	IAMRole            string
	Monitoring         bool
	EBSOptimized       bool
	BlockDevices       []*BlockDeviceMapping
	Tags               map[string]string
	MinCount           int
	MaxCount           int
}

// NewInstanceManager creates a new instance manager
func NewInstanceManager() *InstanceManager {
	manager := &InstanceManager{
		instances:     make(map[string]*Instance),
		instanceTypes: initializeInstanceTypes(),
		images:        initializeAMIs(),
		ipAllocator:   NewIPAllocator(),
		volumeManager: NewVolumeManager(),
		scheduler:     NewInstanceScheduler(),
	}
	
	go manager.scheduler.processOperations()
	return manager
}

// NewIPAllocator creates a new IP allocator
func NewIPAllocator() *IPAllocator {
	allocator := &IPAllocator{
		privateIPPool: make(map[string][]string),
		publicIPPool:  make([]string, 0),
		allocated:     make(map[string]string),
	}
	
	// Initialize public IP pool (simulated)
	for i := 1; i < 255; i++ {
		allocator.publicIPPool = append(allocator.publicIPPool, 
			fmt.Sprintf("203.0.113.%d", i))
	}
	
	// Initialize private IP pools for common subnets
	allocator.initializePrivateIPs("subnet-default", "10.0.1.0/24")
	
	return allocator
}

// initializePrivateIPs sets up private IP pool for a subnet
func (a *IPAllocator) initializePrivateIPs(subnetID, cidr string) {
	// Simplified IP generation for demo
	ips := make([]string, 0)
	for i := 10; i < 250; i++ {
		ips = append(ips, fmt.Sprintf("10.0.1.%d", i))
	}
	a.privateIPPool[subnetID] = ips
}

// AllocatePrivateIP allocates a private IP from subnet pool
func (a *IPAllocator) AllocatePrivateIP(subnetID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	pool, exists := a.privateIPPool[subnetID]
	if !exists || len(pool) == 0 {
		return "", fmt.Errorf("no available private IPs in subnet")
	}
	
	ip := pool[0]
	a.privateIPPool[subnetID] = pool[1:]
	return ip, nil
}

// AllocatePublicIP allocates a public IP
func (a *IPAllocator) AllocatePublicIP(instanceID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if len(a.publicIPPool) == 0 {
		return "", fmt.Errorf("no available public IPs")
	}
	
	ip := a.publicIPPool[0]
	a.publicIPPool = a.publicIPPool[1:]
	a.allocated[instanceID] = ip
	return ip, nil
}

// ReleasePublicIP releases a public IP back to pool
func (a *IPAllocator) ReleasePublicIP(instanceID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	ip, exists := a.allocated[instanceID]
	if !exists {
		return fmt.Errorf("no public IP allocated to instance")
	}
	
	delete(a.allocated, instanceID)
	a.publicIPPool = append(a.publicIPPool, ip)
	return nil
}

// NewVolumeManager creates a new volume manager
func NewVolumeManager() *VolumeManager {
	return &VolumeManager{
		volumes: make(map[string]*Volume),
	}
}

// CreateVolume creates a new EBS volume
func (vm *VolumeManager) CreateVolume(size int, volumeType string, encrypted bool) (*Volume, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	volume := &Volume{
		ID:         fmt.Sprintf("vol-%s", uuid.New().String()[:8]),
		Size:       size,
		VolumeType: volumeType,
		Encrypted:  encrypted,
		State:      "available",
		CreatedAt:  time.Now(),
	}
	
	if volumeType == "io1" || volumeType == "io2" {
		volume.IOPS = size * 50 // Default IOPS calculation
	}
	
	vm.volumes[volume.ID] = volume
	return volume, nil
}

// AttachVolume attaches a volume to an instance
func (vm *VolumeManager) AttachVolume(volumeID, instanceID, device string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	volume, exists := vm.volumes[volumeID]
	if !exists {
		return fmt.Errorf("volume not found")
	}
	
	if volume.State != "available" {
		return fmt.Errorf("volume not available for attachment")
	}
	
	volume.AttachedTo = instanceID
	volume.Device = device
	volume.State = "in-use"
	
	return nil
}

// NewInstanceScheduler creates a new scheduler
func NewInstanceScheduler() *InstanceScheduler {
	return &InstanceScheduler{
		operations: make(chan *InstanceOperation, 100),
	}
}

// processOperations processes pending instance operations
func (s *InstanceScheduler) processOperations() {
	for op := range s.operations {
		// Simulate operation delay
		time.Sleep(time.Duration(500+randomInt(2000)) * time.Millisecond)
		op.CompletedAt = time.Now()
	}
}

// RunInstance launches new EC2 instances
func (m *InstanceManager) RunInstance(req *LaunchInstanceRequest) ([]*Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Validate instance type
	instanceType, exists := m.instanceTypes[req.InstanceType]
	if !exists {
		return nil, fmt.Errorf("invalid instance type: %s", req.InstanceType)
	}
	
	// Validate AMI
	ami, exists := m.images[req.ImageID]
	if !exists {
		return nil, fmt.Errorf("invalid AMI: %s", req.ImageID)
	}
	
	// Set default subnet if not specified
	if req.SubnetID == "" {
		req.SubnetID = "subnet-default"
	}
	
	instances := make([]*Instance, 0)
	count := req.MinCount
	if count == 0 {
		count = 1
	}
	
	for i := 0; i < count; i++ {
		instance, err := m.createInstance(req, instanceType, ami)
		if err != nil {
			return instances, err
		}
		
		m.instances[instance.ID] = instance
		instances = append(instances, instance)
		
		// Schedule launch operation
		m.scheduler.operations <- &InstanceOperation{
			InstanceID: instance.ID,
			Operation:  "launch",
		}
		
		// Start instance monitoring
		go m.monitorInstance(instance)
		
		// Start state transition
		go m.transitionToRunning(instance)
	}
	
	return instances, nil
}

// createInstance creates a new instance object
func (m *InstanceManager) createInstance(req *LaunchInstanceRequest, 
	instanceType *InstanceType, ami *AMI) (*Instance, error) {
	
	instanceID := fmt.Sprintf("i-%s", uuid.New().String()[:17])
	
	// Allocate private IP
	privateIP, err := m.ipAllocator.AllocatePrivateIP(req.SubnetID)
	if err != nil {
		return nil, err
	}
	
	// Allocate public IP if in public subnet
	publicIP := ""
	if !isPrivateSubnet(req.SubnetID) {
		publicIP, _ = m.ipAllocator.AllocatePublicIP(instanceID)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	instance := &Instance{
		ID:                    instanceID,
		Name:                  getNameFromTags(req.Tags),
		InstanceType:          req.InstanceType,
		ImageID:               req.ImageID,
		State:                 StatePending,
		StateReason:           "pending",
		SubnetID:              req.SubnetID,
		PrivateIP:             privateIP,
		PublicIP:              publicIP,
		SecurityGroups:        req.SecurityGroups,
		KeyName:               req.KeyName,
		IAMRole:               req.IAMRole,
		UserData:              req.UserData,
		Tags:                  req.Tags,
		LaunchTime:            time.Now(),
		StateTransitionTime:   time.Now(),
		Monitoring:            req.Monitoring,
		EBSOptimized:          req.EBSOptimized,
		TerminationProtection: false,
		BlockDevices:          make([]*BlockDeviceMapping, 0),
		ctx:                   ctx,
		cancel:                cancel,
	}
	
	// Initialize metrics
	instance.Memory.AvailableMB = instanceType.MemoryMB
	
	// Create and attach root volume
	rootVolume, err := m.volumeManager.CreateVolume(20, "gp3", false)
	if err != nil {
		return nil, err
	}
	
	m.volumeManager.AttachVolume(rootVolume.ID, instance.ID, "/dev/sda1")
	instance.BlockDevices = append(instance.BlockDevices, &BlockDeviceMapping{
		DeviceName:          "/dev/sda1",
		VolumeID:            rootVolume.ID,
		VolumeSize:          20,
		VolumeType:          "gp3",
		DeleteOnTermination: true,
	})
	
	// Create additional volumes
	for _, bd := range req.BlockDevices {
		vol, err := m.volumeManager.CreateVolume(bd.VolumeSize, bd.VolumeType, bd.Encrypted)
		if err != nil {
			continue
		}
		
		m.volumeManager.AttachVolume(vol.ID, instance.ID, bd.DeviceName)
		bd.VolumeID = vol.ID
		instance.BlockDevices = append(instance.BlockDevices, bd)
	}
	
	return instance, nil
}

// transitionToRunning transitions instance from pending to running
func (m *InstanceManager) transitionToRunning(instance *Instance) {
	time.Sleep(3 * time.Second) // Simulate boot time
	
	instance.mu.Lock()
	instance.State = StateRunning
	instance.StateReason = "running"
	instance.StateTransitionTime = time.Now()
	instance.mu.Unlock()
}

// StopInstance stops a running instance
func (m *InstanceManager) StopInstance(instanceID string, force bool) error {
	m.mu.RLock()
	instance, exists := m.instances[instanceID]
	m.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("instance not found")
	}
	
	instance.mu.Lock()
	
	if instance.State != StateRunning {
		instance.mu.Unlock()
		return fmt.Errorf("instance not in running state")
	}
	
	instance.State = StateStopping
	instance.StateReason = "User initiated stop"
	instance.StateTransitionTime = time.Now()
	instance.mu.Unlock()
	
	// Schedule stop operation
	m.scheduler.operations <- &InstanceOperation{
		InstanceID: instanceID,
		Operation:  "stop",
	}
	
	// Transition to stopped
	go func() {
		time.Sleep(2 * time.Second)
		instance.mu.Lock()
		instance.State = StateStopped
		instance.StateReason = "stopped"
		instance.StateTransitionTime = time.Now()
		instance.mu.Unlock()
	}()
	
	return nil
}

// StartInstance starts a stopped instance
func (m *InstanceManager) StartInstance(instanceID string) error {
	m.mu.RLock()
	instance, exists := m.instances[instanceID]
	m.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("instance not found")
	}
	
	instance.mu.Lock()
	
	if instance.State != StateStopped {
		instance.mu.Unlock()
		return fmt.Errorf("instance not in stopped state")
	}
	
	instance.State = StatePending
	instance.StateReason = "User initiated start"
	instance.StateTransitionTime = time.Now()
	instance.mu.Unlock()
	
	// Schedule start operation
	m.scheduler.operations <- &InstanceOperation{
		InstanceID: instanceID,
		Operation:  "start",
	}
	
	go m.transitionToRunning(instance)
	
	return nil
}

// RebootInstance reboots an instance
func (m *InstanceManager) RebootInstance(instanceID string) error {
	m.mu.RLock()
	instance, exists := m.instances[instanceID]
	m.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("instance not found")
	}
	
	instance.mu.Lock()
	
	if instance.State != StateRunning {
		instance.mu.Unlock()
		return fmt.Errorf("instance not in running state")
	}
	
	instance.State = StateRebooting
	instance.StateReason = "User initiated reboot"
	instance.StateTransitionTime = time.Now()
	instance.mu.Unlock()
	
	// Schedule reboot
	go func() {
		time.Sleep(5 * time.Second)
		instance.mu.Lock()
		instance.State = StateRunning
		instance.StateReason = "running"
		instance.StateTransitionTime = time.Now()
		instance.mu.Unlock()
	}()
	
	return nil
}

// TerminateInstance terminates an instance
func (m *InstanceManager) TerminateInstance(instanceID string) error {
	m.mu.RLock()
	instance, exists := m.instances[instanceID]
	m.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("instance not found")
	}
	
	instance.mu.Lock()
	
	if instance.TerminationProtection {
		instance.mu.Unlock()
		return fmt.Errorf("instance has termination protection enabled")
	}
	
	instance.State = StateShuttingDown
	instance.StateReason = "User initiated termination"
	instance.StateTransitionTime = time.Now()
	instance.mu.Unlock()
	
	// Cancel monitoring
	instance.cancel()
	
	// Release public IP
	if instance.PublicIP != "" {
		m.ipAllocator.ReleasePublicIP(instance.ID)
	}
	
	// Delete volumes marked for deletion
	for _, bd := range instance.BlockDevices {
		if bd.DeleteOnTermination {
			m.volumeManager.mu.Lock()
			delete(m.volumeManager.volumes, bd.VolumeID)
			m.volumeManager.mu.Unlock()
		}
	}
	
	// Transition to terminated
	go func() {
		time.Sleep(2 * time.Second)
		instance.mu.Lock()
		instance.State = StateTerminated
		instance.StateReason = "terminated"
		instance.StateTransitionTime = time.Now()
		instance.mu.Unlock()
	}()
	
	return nil
}

// monitorInstance monitors instance metrics
func (m *InstanceManager) monitorInstance(instance *Instance) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-instance.ctx.Done():
			return
		case <-ticker.C:
			instance.mu.RLock()
			if instance.State != StateRunning {
				instance.mu.RUnlock()
				continue
			}
			instance.mu.RUnlock()
			
			// Simulate metrics
			instance.CPU.mu.Lock()
			instance.CPU.UtilizationPercent = float64(randomInt(100))
			instance.CPU.mu.Unlock()
			
			instance.Network.mu.Lock()
			instance.Network.BytesIn += uint64(randomInt(100000))
			instance.Network.BytesOut += uint64(randomInt(100000))
			instance.Network.mu.Unlock()
		}
	}
}

// DescribeInstance returns instance details
func (m *InstanceManager) DescribeInstance(instanceID string) (*Instance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	instance, exists := m.instances[instanceID]
	if !exists {
		return nil, fmt.Errorf("instance not found")
	}
	
	return instance, nil
}

// ListInstances returns all instances
func (m *InstanceManager) ListInstances(filters map[string]string) []*Instance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	instances := make([]*Instance, 0)
	for _, instance := range m.instances {
		if matchesFilters(instance, filters) {
			instances = append(instances, instance)
		}
	}
	
	return instances
}

// Helper functions

func initializeInstanceTypes() map[string]*InstanceType {
	return map[string]*InstanceType{
		"t3.micro":   {Name: "t3.micro", VCPUs: 2, MemoryMB: 1024, StorageGB: 0, NetworkMbps: 5000, PricePerHour: 0.0104},
		"t3.small":   {Name: "t3.small", VCPUs: 2, MemoryMB: 2048, StorageGB: 0, NetworkMbps: 5000, PricePerHour: 0.0208},
		"t3.medium":  {Name: "t3.medium", VCPUs: 2, MemoryMB: 4096, StorageGB: 0, NetworkMbps: 5000, PricePerHour: 0.0416},
		"m5.large":   {Name: "m5.large", VCPUs: 2, MemoryMB: 8192, StorageGB: 0, NetworkMbps: 10000, PricePerHour: 0.096},
		"m5.xlarge":  {Name: "m5.xlarge", VCPUs: 4, MemoryMB: 16384, StorageGB: 0, NetworkMbps: 10000, PricePerHour: 0.192},
		"c5.large":   {Name: "c5.large", VCPUs: 2, MemoryMB: 4096, StorageGB: 0, NetworkMbps: 10000, PricePerHour: 0.085},
		"r5.large":   {Name: "r5.large", VCPUs: 2, MemoryMB: 16384, StorageGB: 0, NetworkMbps: 10000, PricePerHour: 0.126},
	}
}

func initializeAMIs() map[string]*AMI {
	return map[string]*AMI{
		"ami-ubuntu2204": {
			ID: "ami-ubuntu2204", Name: "Ubuntu 22.04 LTS", Platform: "Linux",
			Architecture: "x86_64", CreatedAt: time.Now(), Public: true,
		},
		"ami-amazonlinux2": {
			ID: "ami-amazonlinux2", Name: "Amazon Linux 2", Platform: "Linux",
			Architecture: "x86_64", CreatedAt: time.Now(), Public: true,
		},
	}
}

func getNameFromTags(tags map[string]string) string {
	if name, ok := tags["Name"]; ok {
		return name
	}
	return ""
}

func isPrivateSubnet(subnetID string) bool {
	return subnetID != "subnet-public"
}

func matchesFilters(instance *Instance, filters map[string]string) bool {
	if len(filters) == 0 {
		return true
	}
	
	for key, value := range filters {
		switch key {
		case "instance-state":
			if string(instance.State) != value {
				return false
			}
		case "instance-type":
			if instance.InstanceType != value {
				return false
			}
		}
	}
	return true
}

func randomInt(max int) int {
	return int(time.Now().UnixNano() % int64(max))
}