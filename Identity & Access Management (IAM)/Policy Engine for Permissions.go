package policy

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Example usage of the Policy Engine
func ExamplePolicyEngineUsage() {
	// Initialize database and Redis connections
	db, _ := gorm.Open(postgres.Open("your-db-connection-string"), &gorm.Config{})
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Create policy engine
	pe := NewPolicyEngine(db, redisClient)

	// Migrate tables
	pe.MigratePolicyTables()

	ctx := context.Background()

	// Create system policies
	pe.CreateSystemPolicies(ctx)

	// Example 1: Create a custom policy for a development team
	devTeamPolicy := &Policy{
		Name:        "DevelopmentTeamAccess",
		Description: "Access policy for development team members",
		Type:        CustomPolicy,
		Statements: []PolicyStatement{
			{
				Effect:    Allow,
				Actions:   []string{"repository:read", "repository:write", "build:trigger"},
				Resources: []string{"repository:development/*", "build:development/*"},
			},
			{
				Effect:    Allow,
				Actions:   []string{"deployment:read"},
				Resources: []string{"deployment:staging/*"},
			},
			{
				Effect:    Deny,
				Actions:   []string{"deployment:create", "deployment:delete"},
				Resources: []string{"deployment:production/*"},
			},
		},
	}

	pe.CreatePolicy