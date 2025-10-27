import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
import json
from datetime import datetime

class NetworkProtocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"

class TrafficDirection(Enum):
    INGRESS = "ingress"
    EGRESS = "egress"

@dataclass
class SecurityRule:
    """Firewall rule for network security groups"""
    rule_id: str
    direction: TrafficDirection
    protocol: NetworkProtocol
    port_range: Optional[tuple] = None  # (start, end)
    source_cidr: str = "0.0.0.0/0"
    destination_cidr: str = "0.0.0.0/0"
    action: str = "allow"  # allow or deny
    priority: int = 100

    def matches(self, protocol: str, port: int, source_ip: str, dest_ip: str) -> bool:
        """Check if traffic matches this rule"""
        if self.protocol != NetworkProtocol.ALL and self.protocol.value != protocol:
            return False
        
        if self.port_range and not (self.port_range[0] <= port <= self.port_range[1]):
            return False
        
        source_net = ipaddress.ip_network(self.source_cidr)
        dest_net = ipaddress.ip_network(self.destination_cidr)
        
        if not ipaddress.ip_address(source_ip) in source_net:
            return False
        
        if not ipaddress.ip_address(dest_ip) in dest_net:
            return False
        
        return True

@dataclass
class SecurityGroup:
    """Network security group for controlling traffic"""
    sg_id: str
    name: str
    description: str
    vpc_id: str
    ingress_rules: List[SecurityRule] = field(default_factory=list)
    egress_rules: List[SecurityRule] = field(default_factory=list)
    
    def add_ingress_rule(self, rule: SecurityRule):
        """Add an ingress rule"""
        if rule.direction != TrafficDirection.INGRESS:
            raise ValueError("Rule must be ingress direction")
        self.ingress_rules.append(rule)
        self.ingress_rules.sort(key=lambda r: r.priority)
    
    def add_egress_rule(self, rule: SecurityRule):
        """Add an egress rule"""
        if rule.direction != TrafficDirection.EGRESS:
            raise ValueError("Rule must be egress direction")
        self.egress_rules.append(rule)
        self.egress_rules.sort(key=lambda r: r.priority)
    
    def check_ingress(self, protocol: str, port: int, source_ip: str, dest_ip: str) -> bool:
        """Check if ingress traffic is allowed"""
        for rule in self.ingress_rules:
            if rule.matches(protocol, port, source_ip, dest_ip):
                return rule.action == "allow"
        return False  # Default deny
    
    def check_egress(self, protocol: str, port: int, source_ip: str, dest_ip: str) -> bool:
        """Check if egress traffic is allowed"""
        for rule in self.egress_rules:
            if rule.matches(protocol, port, source_ip, dest_ip):
                return rule.action == "allow"
        return False  # Default deny

@dataclass
class RouteEntry:
    """Route table entry"""
    destination: str  # CIDR block
    target_type: str  # local, internet_gateway, nat_gateway, vpc_peering
    target_id: str
    priority: int = 100

@dataclass
class RouteTable:
    """Route table for subnet routing"""
    rt_id: str
    name: str
    vpc_id: str
    routes: List[RouteEntry] = field(default_factory=list)
    associated_subnets: Set[str] = field(default_factory=set)
    
    def add_route(self, route: RouteEntry):
        """Add a route to the table"""
        self.routes.append(route)
        self.routes.sort(key=lambda r: (r.priority, ipaddress.ip_network(r.destination).prefixlen), reverse=True)
    
    def get_next_hop(self, dest_ip: str) -> Optional[RouteEntry]:
        """Find the most specific route for destination IP"""
        dest_addr = ipaddress.ip_address(dest_ip)
        for route in self.routes:
            if dest_addr in ipaddress.ip_network(route.destination):
                return route
        return None

@dataclass
class Subnet:
    """Subnet within a VPC"""
    subnet_id: str
    name: str
    vpc_id: str
    cidr_block: str
    availability_zone: str
    route_table_id: Optional[str] = None
    is_public: bool = False
    available_ips: int = 0
    
    def __post_init__(self):
        network = ipaddress.ip_network(self.cidr_block)
        # Reserve first 4 and last IP
        self.available_ips = network.num_addresses - 5
    
    def allocate_ip(self) -> Optional[str]:
        """Allocate an IP address from the subnet"""
        if self.available_ips <= 0:
            return None
        
        network = ipaddress.ip_network(self.cidr_block)
        # In real implementation, track allocated IPs
        # For now, just decrement counter
        self.available_ips -= 1
        return str(network.network_address + 5 + (network.num_addresses - 5 - self.available_ips))
    
    def release_ip(self, ip: str):
        """Release an IP address back to the pool"""
        self.available_ips += 1

@dataclass
class InternetGateway:
    """Internet gateway for VPC"""
    igw_id: str
    name: str
    vpc_id: Optional[str] = None
    state: str = "available"
    
    def attach(self, vpc_id: str):
        """Attach to VPC"""
        self.vpc_id = vpc_id
        self.state = "attached"
    
    def detach(self):
        """Detach from VPC"""
        self.vpc_id = None
        self.state = "available"

@dataclass
class NATGateway:
    """NAT gateway for private subnet internet access"""
    nat_id: str
    name: str
    subnet_id: str
    elastic_ip: str
    state: str = "pending"
    
    def activate(self):
        """Activate the NAT gateway"""
        self.state = "available"

@dataclass
class VPCPeering:
    """VPC peering connection"""
    peering_id: str
    name: str
    requester_vpc_id: str
    accepter_vpc_id: str
    requester_cidr: str
    accepter_cidr: str
    state: str = "pending-acceptance"
    
    def accept(self):
        """Accept the peering connection"""
        self.state = "active"
    
    def reject(self):
        """Reject the peering connection"""
        self.state = "rejected"

@dataclass
class NetworkACL:
    """Network Access Control List (subnet-level firewall)"""
    nacl_id: str
    name: str
    vpc_id: str
    ingress_rules: List[SecurityRule] = field(default_factory=list)
    egress_rules: List[SecurityRule] = field(default_factory=list)
    associated_subnets: Set[str] = field(default_factory=set)
    
    def evaluate_ingress(self, protocol: str, port: int, source_ip: str, dest_ip: str) -> bool:
        """Evaluate ingress traffic (rules are evaluated in order)"""
        for rule in sorted(self.ingress_rules, key=lambda r: r.priority):
            if rule.matches(protocol, port, source_ip, dest_ip):
                return rule.action == "allow"
        return False
    
    def evaluate_egress(self, protocol: str, port: int, source_ip: str, dest_ip: str) -> bool:
        """Evaluate egress traffic"""
        for rule in sorted(self.egress_rules, key=lambda r: r.priority):
            if rule.matches(protocol, port, source_ip, dest_ip):
                return rule.action == "allow"
        return False

@dataclass
class FlowLog:
    """VPC flow log entry"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    action: str  # ACCEPT or REJECT
    bytes: int
    packets: int

class VPC:
    """Virtual Private Cloud with software-defined networking"""
    
    def __init__(self, vpc_id: str, name: str, cidr_block: str, tenant_id: str):
        self.vpc_id = vpc_id
        self.name = name
        self.cidr_block = cidr_block
        self.tenant_id = tenant_id
        self.created_at = datetime.now()
        
        # Network components
        self.subnets: Dict[str, Subnet] = {}
        self.route_tables: Dict[str, RouteTable] = {}
        self.security_groups: Dict[str, SecurityGroup] = {}
        self.network_acls: Dict[str, NetworkACL] = {}
        self.internet_gateways: Dict[str, InternetGateway] = {}
        self.nat_gateways: Dict[str, NATGateway] = {}
        self.peering_connections: Dict[str, VPCPeering] = {}
        
        # Flow logs
        self.flow_logs: List[FlowLog] = []
        self.flow_logging_enabled = False
        
        # Create default route table
        self.default_route_table_id = f"rtb-{vpc_id}-default"
        self.create_route_table(self.default_route_table_id, "default", is_default=True)
        
        # Create default security group
        self.default_sg_id = f"sg-{vpc_id}-default"
        self.create_security_group(self.default_sg_id, "default", "Default security group")
        
        # Create default network ACL
        self.default_nacl_id = f"nacl-{vpc_id}-default"
        self.create_network_acl(self.default_nacl_id, "default")
    
    def validate_cidr_overlap(self, new_cidr: str) -> bool:
        """Check if new CIDR block overlaps with existing subnets"""
        new_network = ipaddress.ip_network(new_cidr)
        for subnet in self.subnets.values():
            existing_network = ipaddress.ip_network(subnet.cidr_block)
            if new_network.overlaps(existing_network):
                return False
        return True
    
    def create_subnet(self, subnet_id: str, name: str, cidr_block: str, 
                     availability_zone: str, is_public: bool = False) -> Subnet:
        """Create a subnet in the VPC"""
        # Validate CIDR is within VPC CIDR
        vpc_network = ipaddress.ip_network(self.cidr_block)
        subnet_network = ipaddress.ip_network(cidr_block)
        
        if not subnet_network.subnet_of(vpc_network):
            raise ValueError(f"Subnet CIDR {cidr_block} is not within VPC CIDR {self.cidr_block}")
        
        # Check for overlaps
        if not self.validate_cidr_overlap(cidr_block):
            raise ValueError(f"Subnet CIDR {cidr_block} overlaps with existing subnet")
        
        subnet = Subnet(
            subnet_id=subnet_id,
            name=name,
            vpc_id=self.vpc_id,
            cidr_block=cidr_block,
            availability_zone=availability_zone,
            route_table_id=self.default_route_table_id,
            is_public=is_public
        )
        
        self.subnets[subnet_id] = subnet
        self.route_tables[self.default_route_table_id].associated_subnets.add(subnet_id)
        self.network_acls[self.default_nacl_id].associated_subnets.add(subnet_id)
        
        return subnet
    
    def create_route_table(self, rt_id: str, name: str, is_default: bool = False) -> RouteTable:
        """Create a route table"""
        rt = RouteTable(rt_id=rt_id, name=name, vpc_id=self.vpc_id)
        
        # Add local route
        local_route = RouteEntry(
            destination=self.cidr_block,
            target_type="local",
            target_id="local",
            priority=0
        )
        rt.add_route(local_route)
        
        self.route_tables[rt_id] = rt
        return rt
    
    def associate_route_table(self, rt_id: str, subnet_id: str):
        """Associate a route table with a subnet"""
        if rt_id not in self.route_tables:
            raise ValueError(f"Route table {rt_id} not found")
        if subnet_id not in self.subnets:
            raise ValueError(f"Subnet {subnet_id} not found")
        
        # Remove from old route table
        old_rt_id = self.subnets[subnet_id].route_table_id
        if old_rt_id:
            self.route_tables[old_rt_id].associated_subnets.discard(subnet_id)
        
        # Add to new route table
        self.route_tables[rt_id].associated_subnets.add(subnet_id)
        self.subnets[subnet_id].route_table_id = rt_id
    
    def create_security_group(self, sg_id: str, name: str, description: str) -> SecurityGroup:
        """Create a security group"""
        sg = SecurityGroup(
            sg_id=sg_id,
            name=name,
            description=description,
            vpc_id=self.vpc_id
        )
        
        # Add default egress rule (allow all outbound)
        default_egress = SecurityRule(
            rule_id=f"{sg_id}-egress-default",
            direction=TrafficDirection.EGRESS,
            protocol=NetworkProtocol.ALL,
            action="allow",
            priority=1000
        )
        sg.add_egress_rule(default_egress)
        
        self.security_groups[sg_id] = sg
        return sg
    
    def create_network_acl(self, nacl_id: str, name: str) -> NetworkACL:
        """Create a network ACL"""
        nacl = NetworkACL(
            nacl_id=nacl_id,
            name=name,
            vpc_id=self.vpc_id
        )
        
        # Add default rules (allow all)
        default_ingress = SecurityRule(
            rule_id=f"{nacl_id}-ingress-default",
            direction=TrafficDirection.INGRESS,
            protocol=NetworkProtocol.ALL,
            action="allow",
            priority=32767
        )
        default_egress = SecurityRule(
            rule_id=f"{nacl_id}-egress-default",
            direction=TrafficDirection.EGRESS,
            protocol=NetworkProtocol.ALL,
            action="allow",
            priority=32767
        )
        
        nacl.ingress_rules.append(default_ingress)
        nacl.egress_rules.append(default_egress)
        
        self.network_acls[nacl_id] = nacl
        return nacl
    
    def create_internet_gateway(self, igw_id: str, name: str) -> InternetGateway:
        """Create an internet gateway"""
        igw = InternetGateway(igw_id=igw_id, name=name)
        igw.attach(self.vpc_id)
        self.internet_gateways[igw_id] = igw
        return igw
    
    def create_nat_gateway(self, nat_id: str, name: str, subnet_id: str, elastic_ip: str) -> NATGateway:
        """Create a NAT gateway"""
        if subnet_id not in self.subnets:
            raise ValueError(f"Subnet {subnet_id} not found")
        
        nat = NATGateway(
            nat_id=nat_id,
            name=name,
            subnet_id=subnet_id,
            elastic_ip=elastic_ip
        )
        nat.activate()
        self.nat_gateways[nat_id] = nat
        return nat
    
    def create_peering_connection(self, peering_id: str, name: str, 
                                  accepter_vpc: 'VPC') -> VPCPeering:
        """Create a VPC peering connection"""
        peering = VPCPeering(
            peering_id=peering_id,
            name=name,
            requester_vpc_id=self.vpc_id,
            accepter_vpc_id=accepter_vpc.vpc_id,
            requester_cidr=self.cidr_block,
            accepter_cidr=accepter_vpc.cidr_block
        )
        
        self.peering_connections[peering_id] = peering
        accepter_vpc.peering_connections[peering_id] = peering
        
        return peering
    
    def enable_flow_logs(self):
        """Enable VPC flow logging"""
        self.flow_logging_enabled = True
    
    def log_flow(self, source_ip: str, dest_ip: str, source_port: int, 
                 dest_port: int, protocol: str, action: str, bytes_transferred: int, packets: int):
        """Log a flow entry"""
        if self.flow_logging_enabled:
            log = FlowLog(
                timestamp=datetime.now(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                action=action,
                bytes=bytes_transferred,
                packets=packets
            )
            self.flow_logs.append(log)
    
    def evaluate_traffic(self, source_ip: str, dest_ip: str, source_port: int,
                        dest_port: int, protocol: str, security_group_ids: List[str]) -> bool:
        """Evaluate if traffic is allowed through all security layers"""
        
        # Check Network ACLs first (subnet level)
        source_subnet = self._find_subnet_for_ip(source_ip)
        dest_subnet = self._find_subnet_for_ip(dest_ip)
        
        if source_subnet:
            nacl = self._get_nacl_for_subnet(source_subnet.subnet_id)
            if nacl and not nacl.evaluate_egress(protocol, source_port, source_ip, dest_ip):
                self.log_flow(source_ip, dest_ip, source_port, dest_port, protocol, "REJECT", 0, 0)
                return False
        
        if dest_subnet:
            nacl = self._get_nacl_for_subnet(dest_subnet.subnet_id)
            if nacl and not nacl.evaluate_ingress(protocol, dest_port, source_ip, dest_ip):
                self.log_flow(source_ip, dest_ip, source_port, dest_port, protocol, "REJECT", 0, 0)
                return False
        
        # Check Security Groups (instance level)
        for sg_id in security_group_ids:
            if sg_id not in self.security_groups:
                continue
            
            sg = self.security_groups[sg_id]
            if not sg.check_ingress(protocol, dest_port, source_ip, dest_ip):
                self.log_flow(source_ip, dest_ip, source_port, dest_port, protocol, "REJECT", 0, 0)
                return False
        
        self.log_flow(source_ip, dest_ip, source_port, dest_port, protocol, "ACCEPT", 1500, 1)
        return True
    
    def _find_subnet_for_ip(self, ip: str) -> Optional[Subnet]:
        """Find which subnet contains the given IP"""
        ip_addr = ipaddress.ip_address(ip)
        for subnet in self.subnets.values():
            if ip_addr in ipaddress.ip_network(subnet.cidr_block):
                return subnet
        return None
    
    def _get_nacl_for_subnet(self, subnet_id: str) -> Optional[NetworkACL]:
        """Get the network ACL associated with a subnet"""
        for nacl in self.network_acls.values():
            if subnet_id in nacl.associated_subnets:
                return nacl
        return None
    
    def get_routing_path(self, source_ip: str, dest_ip: str) -> List[str]:
        """Determine the routing path for traffic"""
        path = []
        
        source_subnet = self._find_subnet_for_ip(source_ip)
        if not source_subnet:
            return ["Source IP not in VPC"]
        
        path.append(f"Source: {source_subnet.name} ({source_subnet.cidr_block})")
        
        # Get route table for source subnet
        rt = self.route_tables.get(source_subnet.route_table_id)
        if not rt:
            return path + ["No route table found"]
        
        # Find next hop
        next_hop = rt.get_next_hop(dest_ip)
        if not next_hop:
            return path + ["No route found"]
        
        path.append(f"Route: {next_hop.destination} -> {next_hop.target_type} ({next_hop.target_id})")
        
        # Check if destination is in VPC
        dest_subnet = self._find_subnet_for_ip(dest_ip)
        if dest_subnet:
            path.append(f"Destination: {dest_subnet.name} ({dest_subnet.cidr_block})")
        else:
            path.append(f"Destination: External ({dest_ip})")
        
        return path
    
    def get_statistics(self) -> Dict:
        """Get VPC statistics"""
        total_ips = ipaddress.ip_network(self.cidr_block).num_addresses
        allocated_ips = sum(
            ipaddress.ip_network(s.cidr_block).num_addresses 
            for s in self.subnets.values()
        )
        
        return {
            "vpc_id": self.vpc_id,
            "name": self.name,
            "cidr_block": self.cidr_block,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "subnets": len(self.subnets),
            "route_tables": len(self.route_tables),
            "security_groups": len(self.security_groups),
            "network_acls": len(self.network_acls),
            "internet_gateways": len(self.internet_gateways),
            "nat_gateways": len(self.nat_gateways),
            "peering_connections": len(self.peering_connections),
            "total_ips": total_ips,
            "allocated_ips": allocated_ips,
            "available_ips": total_ips - allocated_ips,
            "flow_logs_enabled": self.flow_logging_enabled,
            "flow_logs_count": len(self.flow_logs)
        }
    
    def to_dict(self) -> Dict:
        """Convert VPC to dictionary"""
        return {
            "vpc_id": self.vpc_id,
            "name": self.name,
            "cidr_block": self.cidr_block,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "subnets": {k: v.__dict__ for k, v in self.subnets.items()},
            "security_groups": len(self.security_groups),
            "statistics": self.get_statistics()
        }


# Example usage demonstrating VPC with software-defined networking
if __name__ == "__main__":
    print("=== Cloud Hosting Service - VPC Demo ===\n")
    
    # Create a VPC
    vpc = VPC(
        vpc_id="vpc-001",
        name="production-vpc",
        cidr_block="10.0.0.0/16",
        tenant_id="tenant-123"
    )
    
    print(f"Created VPC: {vpc.name}")
    print(f"CIDR Block: {vpc.cidr_block}")
    print(f"Available IPs: {ipaddress.ip_network(vpc.cidr_block).num_addresses}\n")
    
    # Create subnets in different availability zones
    public_subnet = vpc.create_subnet(
        subnet_id="subnet-public-1",
        name="public-subnet-az1",
        cidr_block="10.0.1.0/24",
        availability_zone="az1",
        is_public=True
    )
    
    private_subnet = vpc.create_subnet(
        subnet_id="subnet-private-1",
        name="private-subnet-az1",
        cidr_block="10.0.10.0/24",
        availability_zone="az1",
        is_public=False
    )
    
    print(f"Created public subnet: {public_subnet.name}")
    print(f"  CIDR: {public_subnet.cidr_block}")
    print(f"  Available IPs: {public_subnet.available_ips}\n")
    
    print(f"Created private subnet: {private_subnet.name}")
    print(f"  CIDR: {private_subnet.cidr_block}")
    print(f"  Available IPs: {private_subnet.available_ips}\n")
    
    # Create Internet Gateway
    igw = vpc.create_internet_gateway("igw-001", "main-igw")
    print(f"Created Internet Gateway: {igw.name} (State: {igw.state})\n")
    
    # Create custom route table for public subnet
    public_rt = vpc.create_route_table("rtb-public", "public-route-table")
    public_rt.add_route(RouteEntry(
        destination="0.0.0.0/0",
        target_type="internet_gateway",
        target_id=igw.igw_id,
        priority=100
    ))
    vpc.associate_route_table(public_rt.rt_id, public_subnet.subnet_id)
    print(f"Created public route table with internet gateway route\n")
    
    # Create NAT Gateway for private subnet
    nat = vpc.create_nat_gateway(
        nat_id="nat-001",
        name="main-nat",
        subnet_id=public_subnet.subnet_id,
        elastic_ip="203.0.113.5"
    )
    print(f"Created NAT Gateway: {nat.name} (EIP: {nat.elastic_ip})\n")
    
    # Create route table for private subnet
    private_rt = vpc.create_route_table("rtb-private", "private-route-table")
    private_rt.add_route(RouteEntry(
        destination="0.0.0.0/0",
        target_type="nat_gateway",
        target_id=nat.nat_id,
        priority=100
    ))
    vpc.associate_route_table(private_rt.rt_id, private_subnet.subnet_id)
    print(f"Created private route table with NAT gateway route\n")
    
    # Create Security Group for web servers
    web_sg = vpc.create_security_group(
        sg_id="sg-web",
        name="web-servers",
        description="Security group for web servers"
    )
    
    # Add ingress rules for HTTP and HTTPS
    web_sg.add_ingress_rule(SecurityRule(
        rule_id="sg-web-http",
        direction=TrafficDirection.INGRESS,
        protocol=NetworkProtocol.TCP,
        port_range=(80, 80),
        source_cidr="0.0.0.0/0",
        action="allow",
        priority=100
    ))
    
    web_sg.add_ingress_rule(SecurityRule(
        rule_id="sg-web-https",
        direction=TrafficDirection.INGRESS,
        protocol=NetworkProtocol.TCP,
        port_range=(443, 443),
        source_cidr="0.0.0.0/0",
        action="allow",
        priority=101
    ))
    
    print(f"Created security group: {web_sg.name}")
    print(f"  Ingress rules: {len(web_sg.ingress_rules)}")
    print(f"  Egress rules: {len(web_sg.egress_rules)}\n")
    
    # Enable flow logs
    vpc.enable_flow_logs()
    print("Enabled VPC flow logs\n")
    
    # Test traffic evaluation
    print("=== Traffic Evaluation Tests ===\n")
    
    # Test 1: HTTP traffic to web server
    allowed = vpc.evaluate_traffic(
        source_ip="203.0.113.100",
        dest_ip="10.0.1.10",
        source_port=54321,
        dest_port=80,
        protocol="tcp",
        security_group_ids=["sg-web"]
    )
    print(f"Test 1 - HTTP from internet to web server: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Test 2: SSH traffic (should be blocked)
    allowed = vpc.evaluate_traffic(
        source_ip="203.0.113.100",
        dest_ip="10.0.1.10",
        source_port=54322,
        dest_port=22,
        protocol="tcp",
        security_group_ids=["sg-web"]
    )
    print(f"Test 2 - SSH from internet to web server: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Show routing paths
    print("\n=== Routing Paths ===\n")
    
    path1 = vpc.get_routing_path("10.0.1.10", "8.8.8.8")
    print("Path from public subnet to internet:")
    for step in path1:
        print(f"  -> {step}")
    
    print()
    
    path2 = vpc.get_routing_path("10.0.10.10", "8.8.8.8")
    print("Path from private subnet to internet:")
    for step in path2:
        print(f"  -> {step}")
    
    # Display VPC statistics
    print("\n=== VPC Statistics ===\n")
    stats = vpc.get_statistics()
    for key, value in stats.items():
        if key != "created_at":
            print(f"{key}: {value}")
    
    print("\n=== Flow Logs ===\n")
    print(f"Total flow log entries: {len(vpc.flow_logs)}")
    if vpc.flow_logs:
        print("\nRecent flow logs:")
        for log in vpc.flow_logs[-5:]:
            print(f"  {log.timestamp.strftime('%H:%M:%S')} | "
                  f"{log.source_ip}:{log.source_port} -> "
                  f"{log.dest_ip}:{log.dest_port} | "
                  f"{log.protocol.upper()} | {log.action} | "
                  f"{log.bytes} bytes, {log.packets} packets")