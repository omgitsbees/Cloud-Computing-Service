package vpc

import (
	"fmt"
	"testing"
)

func TestVPCNetworkingComplete(t *testing.T) {
	// Initialize managers
	subnetMgr := NewSubnetManager()
	routeTableMgr := NewRouteTableManager()
	securityGroupMgr := NewSecurityGroupManager()

	// ========================================================================
	// SCENARIO: Set up a VPC with public and private subnets
	// ========================================================================
	
	vpcID := "vpc-12345678"
	vpcCIDR := "10.0.0.0/16"
	
	fmt.Println("=== Setting up VPC Networking ===")
	
	// Register VPC
	if err := subnetMgr.RegisterVPC(vpcID, vpcCIDR); err != nil {
		t.Fatalf("Failed to register VPC: %v", err)
	}
	fmt.Printf("✓ Registered VPC %s with CIDR %s\n", vpcID, vpcCIDR)

	// ========================================================================
	// CREATE SUBNETS
	// ========================================================================
	
	// Create public subnet in AZ-1
	publicSubnet1, err := subnetMgr.CreateSubnet(
		vpcID,
		"public-subnet-az1",
		"10.0.1.0/24",
		"us-east-1a",
		SubnetTypePublic,
	)
	if err != nil {
		t.Fatalf("Failed to create public subnet: %v", err)
	}
	fmt.Printf("✓ Created public subnet %s (%s) with %d available IPs\n", 
		publicSubnet1.ID, publicSubnet1.CIDRBlock, publicSubnet1.AvailableIPCount)

	// Create private subnet in AZ-1
	privateSubnet1, err := subnetMgr.CreateSubnet(
		vpcID,
		"private-subnet-az1",
		"10.0.10.0/24",
		"us-east-1a",
		SubnetTypePrivate,
	)
	if err != nil {
		t.Fatalf("Failed to create private subnet: %v", err)
	}
	fmt.Printf("✓ Created private subnet %s (%s) with %d available IPs\n", 
		privateSubnet1.ID, privateSubnet1.CIDRBlock, privateSubnet1.AvailableIPCount)

	// Create public subnet in AZ-2 for high availability
	publicSubnet2, err := subnetMgr.CreateSubnet(
		vpcID,
		"public-subnet-az2",
		"10.0.2.0/24",
		"us-east-1b",
		SubnetTypePublic,
	)
	if err != nil {
		t.Fatalf("Failed to create second public subnet: %v", err)
	}
	fmt.Printf("✓ Created public subnet %s (%s) in second AZ\n", 
		publicSubnet2.ID, publicSubnet2.CIDRBlock)

	// Test overlapping subnet prevention
	_, err = subnetMgr.CreateSubnet(vpcID, "overlap-test", "10.0.1.128/25", "us-east-1a", SubnetTypePrivate)
	if err == nil {
		t.Fatal("Should have prevented overlapping subnet creation")
	}
	fmt.Println("✓ Correctly prevented overlapping subnet creation")

	// ========================================================================
	// CREATE ROUTE TABLES
	// ========================================================================
	
	// Create main route table
	mainRouteTable, err := routeTableMgr.CreateRouteTable(vpcID, "main-route-table", true)
	if err != nil {
		t.Fatalf("Failed to create main route table: %v", err)
	}
	fmt.Printf("✓ Created main route table %s\n", mainRouteTable.ID)

	// Create public route table
	publicRouteTable, err := routeTableMgr.CreateRouteTable(vpcID, "public-route-table", false)
	if err != nil {
		t.Fatalf("Failed to create public route table: %v", err)
	}
	fmt.Printf("✓ Created public route table %s\n", publicRouteTable.ID)

	// Create private route table
	privateRouteTable, err := routeTableMgr.CreateRouteTable(vpcID, "private-route-table", false)
	if err != nil {
		t.Fatalf("Failed to create private route table: %v", err)
	}
	fmt.Printf("✓ Created private route table %s\n", privateRouteTable.ID)

	// Add internet gateway route to public route table
	igwID := "igw-abc123"
	if err := routeTableMgr.AddRoute(publicRouteTable.ID, "0.0.0.0/0", igwID, "internet-gateway"); err != nil {
		t.Fatalf("Failed to add internet gateway route: %v", err)
	}
	fmt.Printf("✓ Added internet gateway route to public route table\n")

	// Add NAT gateway route to private route table
	natGatewayID := "nat-xyz789"
	if err := routeTableMgr.AddRoute(privateRouteTable.ID, "0.0.0.0/0", natGatewayID, "nat-gateway"); err != nil {
		t.Fatalf("Failed to add NAT gateway route: %v", err)
	}
	fmt.Printf("✓ Added NAT gateway route to private route table\n")

	// Associate route tables with subnets
	if err := routeTableMgr.AssociateSubnet(publicRouteTable.ID, publicSubnet1.ID); err != nil {
		t.Fatalf("Failed to associate public route table: %v", err)
	}
	if err := routeTableMgr.AssociateSubnet(publicRouteTable.ID, publicSubnet2.ID); err != nil {
		t.Fatalf("Failed to associate public route table: %v", err)
	}
	if err := routeTableMgr.AssociateSubnet(privateRouteTable.ID, privateSubnet1.ID); err != nil {
		t.Fatalf("Failed to associate private route table: %v", err)
	}
	fmt.Println("✓ Associated route tables with subnets")

	// Update subnet references
	subnetMgr.AssociateRouteTable(publicSubnet1.ID, publicRouteTable.ID)
	subnetMgr.AssociateRouteTable(publicSubnet2.ID, publicRouteTable.ID)
	subnetMgr.AssociateRouteTable(privateSubnet1.ID, privateRouteTable.ID)

	// ========================================================================
	// CREATE SECURITY GROUPS
	// ========================================================================
	
	// Create web server security group
	webSG, err := securityGroupMgr.CreateSecurityGroup(
		vpcID,
		"web-server-sg",
		"Security group for web servers",
	)
	if err != nil {
		t.Fatalf("Failed to create web security group: %v", err)
	}
	fmt.Printf("✓ Created web server security group %s\n", webSG.ID)

	// Add HTTP ingress rule
	if err := securityGroupMgr.AddRule(
		webSG.ID,
		RuleTypeIngress,
		ProtocolTCP,
		80,
		80,
		"0.0.0.0/0",
		"Allow HTTP from anywhere",
	); err != nil {
		t.Fatalf("Failed to add HTTP rule: %v", err)
	}

	// Add HTTPS ingress rule
	if err := securityGroupMgr.AddRule(
		webSG.ID,
		RuleTypeIngress,
		ProtocolTCP,
		443,
		443,
		"0.0.0.0/0",
		"Allow HTTPS from anywhere",
	); err != nil {
		t.Fatalf("Failed to add HTTPS rule: %v", err)
	}

	// Add SSH ingress rule (restricted)
	if err := securityGroupMgr.AddRule(
		webSG.ID,
		RuleTypeIngress,
		ProtocolTCP,
		22,
		22,
		"203.0.113.0/24",
		"Allow SSH from office",
	); err != nil {
		t.Fatalf("Failed to add SSH rule: %v", err)
	}
	fmt.Println("✓ Added ingress rules to web security group")

	// Create database security group
	dbSG, err := securityGroupMgr.CreateSecurityGroup(
		vpcID,
		"database-sg",
		"Security group for database servers",
	)
	if err != nil {
		t.Fatalf("Failed to create database security group: %v", err)
	}
	fmt.Printf("✓ Created database security group %s\n", dbSG.ID)

	// Add PostgreSQL ingress rule (only from web servers)
	if err := securityGroupMgr.AddRule(
		dbSG.ID,
		RuleTypeIngress,
		ProtocolTCP,
		5432,
		5432,
		webSG.ID,
		"Allow PostgreSQL from web servers",
	); err != nil {
		t.Fatalf("Failed to add PostgreSQL rule: %v", err)
	}
	fmt.Println("✓ Added PostgreSQL rule to database security group")

	// ========================================================================
	// TEST TRAFFIC EVALUATION
	// ========================================================================
	
	fmt.Println("\n=== Testing Traffic Evaluation ===")

	// Test allowed HTTP traffic
	allowed := securityGroupMgr.EvaluateTraffic(webSG.ID, RuleTypeIngress, ProtocolTCP, 80, "1.2.3.4")
	if !allowed {
		t.Error("HTTP traffic should be allowed")
	}
	fmt.Println("✓ HTTP traffic from internet: ALLOWED")

	// Test allowed HTTPS traffic
	allowed = securityGroupMgr.EvaluateTraffic(webSG.ID, RuleTypeIngress, ProtocolTCP, 443, "1.2.3.4")
	if !allowed {
		t.Error("HTTPS traffic should be allowed")
	}
	fmt.Println("✓ HTTPS traffic from internet: ALLOWED")

	// Test SSH from office (allowed)
	allowed = securityGroupMgr.EvaluateTraffic(webSG.ID, RuleTypeIngress, ProtocolTCP, 22, "203.0.113.5")
	if !allowed {
		t.Error("SSH from office should be allowed")
	}
	fmt.Println("✓ SSH from office network: ALLOWED")

	// Test SSH from random IP (blocked)
	blocked := !securityGroupMgr.EvaluateTraffic(webSG.ID, RuleTypeIngress, ProtocolTCP, 22, "1.2.3.4")
	if !blocked {
		t.Error("SSH from random IP should be blocked")
	}
	fmt.Println("✓ SSH from random IP: BLOCKED")

	// Test outbound traffic (egress default allow all)
	allowed = securityGroupMgr.EvaluateTraffic(webSG.ID, RuleTypeEgress, ProtocolTCP, 443, "0.0.0.0/0")
	if !allowed {
		t.Error("Outbound HTTPS should be allowed")
	}
	fmt.Println("✓ Outbound HTTPS traffic: ALLOWED")

	// ========================================================================
	// DISPLAY CONFIGURATION SUMMARY
	// ========================================================================
	
	fmt.Println("\n=== Configuration Summary ===")
	
	fmt.Println("\nSubnets:")
	for _, subnet := range subnetMgr.ListSubnets(vpcID) {
		fmt.Printf("  - %s (%s): %s [%s] - %d IPs, Route Table: %s\n",
			subnet.Name,
			subnet.ID,
			subnet.CIDRBlock,
			subnet.Type,
			subnet.AvailableIPCount,
			subnet.RouteTableID,
		)
	}

	fmt.Println("\nRoute Tables:")
	for _, rt := range routeTableMgr.ListRouteTables(vpcID) {
		fmt.Printf("  - %s (%s):\n", rt.Name, rt.ID)
		for _, route := range rt.Routes {
			fmt.Printf("      %s -> %s (%s)\n", 
				route.DestinationCIDR, 
				route.Target, 
				route.TargetType,
			)
		}
		fmt.Printf("      Associated Subnets: %d\n", len(rt.AssociatedSubnets))
	}

	fmt.Println("\nSecurity Groups:")
	for _, sg := range securityGroupMgr.ListSecurityGroups(vpcID) {
		fmt.Printf("  - %s (%s): %s\n", sg.Name, sg.ID, sg.Description)
		fmt.Printf("      Ingress Rules: %d, Egress Rules: %d\n",
			countRulesByType(sg.Rules, RuleTypeIngress),
			countRulesByType(sg.Rules, RuleTypeEgress),
		)
	}

	// ========================================================================
	// TEST CLEANUP OPERATIONS
	// ========================================================================
	
	fmt.Println("\n=== Testing Cleanup Operations ===")

	// Delete a route
	if err := routeTableMgr.DeleteRoute(publicRouteTable.ID, "0.0.0.0/0"); err != nil {
		t.Fatalf("Failed to delete route: %v", err)
	}
	fmt.Println("✓ Deleted internet gateway route")

	// Remove security group rule
	ruleToDelete := webSG.Rules[1].ID
	if err := securityGroupMgr.DeleteRule(webSG.ID, ruleToDelete); err != nil {
		t.Fatalf("Failed to delete security group rule: %v", err)
	}
	fmt.Println("✓ Deleted security group rule")

	// Disassociate route table from subnet
	if err := routeTableMgr.DisassociateSubnet(publicRouteTable.ID, publicSubnet1.ID); err != nil {
		t.Fatalf("Failed to disassociate route table: %v", err)
	}
	fmt.Println("✓ Disassociated route table from subnet")

	fmt.Println("\n=== All Tests Passed! ===")
}

// Helper function
func countRulesByType(rules []SecurityGroupRule, ruleType RuleType) int {
	count := 0
	for _, rule := range rules {
		if rule.Type == ruleType {
			count++
		}
	}
	return count
}

// Benchmark tests
func BenchmarkSubnetCreation(b *testing.B) {
	sm := NewSubnetManager()
	sm.RegisterVPC("vpc-test", "10.0.0.0/16")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cidr := fmt.Sprintf("10.0.%d.0/24", i%256)
		sm.CreateSubnet("vpc-test", "test-subnet", cidr, "us-east-1a", SubnetTypePrivate)
	}
}

func BenchmarkSecurityGroupEvaluation(b *testing.B) {
	sgm := NewSecurityGroupManager()
	sg, _ := sgm.CreateSecurityGroup("vpc-test", "test-sg", "test")
	sgm.AddRule(sg.ID, RuleTypeIngress, ProtocolTCP, 80, 80, "0.0.0.0/0", "test")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sgm.EvaluateTraffic(sg.ID, RuleTypeIngress, ProtocolTCP, 80, "1.2.3.4")
	}
}