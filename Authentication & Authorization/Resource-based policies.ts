// Resource-Based Policies Implementation
// This extends your existing JWT/OAuth2 and RBAC system

// Types and Interfaces
interface ResourcePolicy {
  id: string;
  resourceType: string;
  resourceId: string;
  version: string;
  statements: PolicyStatement[];
  createdAt: Date;
  updatedAt: Date;
}

interface PolicyStatement {
  sid?: string; // Statement ID
  effect: 'Allow' | 'Deny';
  principal: Principal;
  action: string | string[];
  resource: string | string[];
  condition?: PolicyCondition;
}

interface Principal {
  type: 'User' | 'Role' | 'Service' | 'Group' | '*';
  identifiers: string[];
}

interface PolicyCondition {
  operator: 'StringEquals' | 'StringNotEquals' | 'NumericEquals' | 'NumericLessThan' | 
           'NumericGreaterThan' | 'DateTimeAfter' | 'DateTimeBefore' | 'IpAddress' | 
           'NotIpAddress' | 'Bool' | 'StringLike';
  key: string;
  value: string | number | boolean | string[];
}

enum ResourceType {
  STORAGE_BUCKET = 'storage:bucket',
  DATABASE = 'database:instance',
  COMPUTE_INSTANCE = 'compute:instance',
  NETWORK = 'network:vpc',
  SECRET = 'secret:item'
}

// Resource Policy Engine
class ResourcePolicyEngine {
  private policies: Map<string, ResourcePolicy[]> = new Map();
  private cache: Map<string, boolean> = new Map();
  private cacheTimeout = 5 * 60 * 1000; // 5 minutes

  constructor() {
    this.setupDefaultPolicies();
  }

  // Attach policy to a resource
  async attachPolicy(resourceId: string, policy: ResourcePolicy): Promise<void> {
    const resourcePolicies = this.policies.get(resourceId) || [];
    
    // Check for policy conflicts
    this.validatePolicyConflicts(resourcePolicies, policy);
    
    resourcePolicies.push(policy);
    this.policies.set(resourceId, resourcePolicies);
    
    // Invalidate cache for this resource
    this.invalidateCache(resourceId);
    
    console.log(`Policy ${policy.id} attached to resource ${resourceId}`);
  }

  // Detach policy from resource
  async detachPolicy(resourceId: string, policyId: string): Promise<void> {
    const resourcePolicies = this.policies.get(resourceId) || [];
    const updatedPolicies = resourcePolicies.filter(p => p.id !== policyId);
    
    this.policies.set(resourceId, updatedPolicies);
    this.invalidateCache(resourceId);
    
    console.log(`Policy ${policyId} detached from resource ${resourceId}`);
  }

  // Evaluate access request
  async evaluateAccess(request: AccessRequest): Promise<AccessResult> {
    const cacheKey = this.generateCacheKey(request);
    
    // Check cache first
    const cachedResult = this.getFromCache(cacheKey);
    if (cachedResult !== null) {
      return { allowed: cachedResult, cached: true };
    }

    const resourcePolicies = this.policies.get(request.resourceId) || [];
    let explicitAllow = false;
    let explicitDeny = false;

    // Evaluate each policy statement
    for (const policy of resourcePolicies) {
      for (const statement of policy.statements) {
        if (this.statementMatches(statement, request)) {
          if (statement.effect === 'Allow') {
            explicitAllow = true;
          } else if (statement.effect === 'Deny') {
            explicitDeny = true;
            // Deny takes precedence - short circuit
            this.setCache(cacheKey, false);
            return { allowed: false, reason: 'Explicit deny', cached: false };
          }
        }
      }
    }

    const allowed = explicitAllow;
    this.setCache(cacheKey, allowed);
    
    return { 
      allowed, 
      reason: allowed ? 'Policy allowed' : 'No explicit allow',
      cached: false 
    };
  }

  // Check if statement matches the request
  private statementMatches(statement: PolicyStatement, request: AccessRequest): boolean {
    // Check principal
    if (!this.principalMatches(statement.principal, request.principal)) {
      return false;
    }

    // Check action
    if (!this.actionMatches(statement.action, request.action)) {
      return false;
    }

    // Check resource
    if (!this.resourceMatches(statement.resource, request.resourceArn)) {
      return false;
    }

    // Check conditions
    if (statement.condition && !this.conditionMatches(statement.condition, request)) {
      return false;
    }

    return true;
  }

  private principalMatches(policyPrincipal: Principal, requestPrincipal: string): boolean {
    if (policyPrincipal.type === '*') return true;
    
    return policyPrincipal.identifiers.includes(requestPrincipal) ||
           policyPrincipal.identifiers.includes('*');
  }

  private actionMatches(policyActions: string | string[], requestAction: string): boolean {
    const actions = Array.isArray(policyActions) ? policyActions : [policyActions];
    
    return actions.some(action => {
      if (action === '*') return true;
      if (action.endsWith('*')) {
        const prefix = action.slice(0, -1);
        return requestAction.startsWith(prefix);
      }
      return action === requestAction;
    });
  }

  private resourceMatches(policyResources: string | string[], requestResource: string): boolean {
    const resources = Array.isArray(policyResources) ? policyResources : [policyResources];
    
    return resources.some(resource => {
      if (resource === '*') return true;
      if (resource.endsWith('*')) {
        const prefix = resource.slice(0, -1);
        return requestResource.startsWith(prefix);
      }
      return resource === requestResource;
    });
  }

  private conditionMatches(condition: PolicyCondition, request: AccessRequest): boolean {
    const contextValue = request.context?.[condition.key];
    
    if (contextValue === undefined) return false;

    switch (condition.operator) {
      case 'StringEquals':
        return contextValue === condition.value;
      case 'StringNotEquals':
        return contextValue !== condition.value;
      case 'NumericEquals':
        return Number(contextValue) === Number(condition.value);
      case 'NumericLessThan':
        return Number(contextValue) < Number(condition.value);
      case 'NumericGreaterThan':
        return Number(contextValue) > Number(condition.value);
      case 'IpAddress':
        return this.isIpInRange(contextValue, condition.value as string);
      case 'Bool':
        return Boolean(contextValue) === Boolean(condition.value);
      case 'StringLike':
        return this.matchesWildcard(contextValue, condition.value as string);
      default:
        return false;
    }
  }

  private isIpInRange(ip: string, range: string): boolean {
    // Simplified IP range check - in production, use a proper IP library
    if (range.includes('/')) {
      // CIDR notation
      return true; // Implement CIDR matching
    }
    return ip === range;
  }

  private matchesWildcard(value: string, pattern: string): boolean {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(value);
  }

  private validatePolicyConflicts(existingPolicies: ResourcePolicy[], newPolicy: ResourcePolicy): void {
    // Check for conflicting statements
    for (const existing of existingPolicies) {
      for (const existingStmt of existing.statements) {
        for (const newStmt of newPolicy.statements) {
          if (this.statementsConflict(existingStmt, newStmt)) {
            console.warn(`Potential policy conflict detected between ${existing.id} and ${newPolicy.id}`);
          }
        }
      }
    }
  }

  private statementsConflict(stmt1: PolicyStatement, stmt2: PolicyStatement): boolean {
    // Same principal, action, resource but different effects
    return stmt1.effect !== stmt2.effect &&
           JSON.stringify(stmt1.principal) === JSON.stringify(stmt2.principal) &&
           JSON.stringify(stmt1.action) === JSON.stringify(stmt2.action) &&
           JSON.stringify(stmt1.resource) === JSON.stringify(stmt2.resource);
  }

  // Cache management
  private generateCacheKey(request: AccessRequest): string {
    return `${request.principal}:${request.action}:${request.resourceId}:${JSON.stringify(request.context)}`;
  }

  private getFromCache(key: string): boolean | null {
    // Simple cache implementation - in production, use Redis
    return this.cache.get(key) ?? null;
  }

  private setCache(key: string, value: boolean): void {
    this.cache.set(key, value);
    setTimeout(() => this.cache.delete(key), this.cacheTimeout);
  }

  private invalidateCache(resourceId: string): void {
    // Remove all cache entries related to this resource
    for (const [key, _] of this.cache) {
      if (key.includes(resourceId)) {
        this.cache.delete(key);
      }
    }
  }

  private setupDefaultPolicies(): void {
    // Setup some default policies for common scenarios
    console.log('Resource Policy Engine initialized with default policies');
  }
}

// Request and Response types
interface AccessRequest {
  principal: string; // User ID, role, or service
  action: string; // e.g., 'storage:GetObject', 'compute:StartInstance'
  resourceId: string;
  resourceArn: string; // Amazon Resource Name format
  context?: { [key: string]: any }; // Additional context like IP, time, etc.
}

interface AccessResult {
  allowed: boolean;
  reason?: string;
  cached: boolean;
}

// Policy Builder for easier policy creation
class PolicyBuilder {
  private policy: Partial<ResourcePolicy> = {
    statements: []
  };

  static create(resourceType: string, resourceId: string): PolicyBuilder {
    const builder = new PolicyBuilder();
    builder.policy.resourceType = resourceType;
    builder.policy.resourceId = resourceId;
    builder.policy.id = `policy-${Date.now()}`;
    builder.policy.version = '2024-01-01';
    builder.policy.createdAt = new Date();
    builder.policy.updatedAt = new Date();
    return builder;
  }

  allowPrincipal(principalType: Principal['type'], identifiers: string[]): PolicyBuilder {
    return this.addStatement('Allow', { type: principalType, identifiers });
  }

  denyPrincipal(principalType: Principal['type'], identifiers: string[]): PolicyBuilder {
    return this.addStatement('Deny', { type: principalType, identifiers });
  }

  private addStatement(effect: 'Allow' | 'Deny', principal: Principal): PolicyBuilder {
    this.policy.statements!.push({
      effect,
      principal,
      action: '*',
      resource: '*'
    });
    return this;
  }

  withAction(action: string | string[]): PolicyBuilder {
    const lastStatement = this.policy.statements![this.policy.statements!.length - 1];
    lastStatement.action = action;
    return this;
  }

  withResource(resource: string | string[]): PolicyBuilder {
    const lastStatement = this.policy.statements![this.policy.statements!.length - 1];
    lastStatement.resource = resource;
    return this;
  }

  withCondition(operator: PolicyCondition['operator'], key: string, value: any): PolicyBuilder {
    const lastStatement = this.policy.statements![this.policy.statements!.length - 1];
    lastStatement.condition = { operator, key, value };
    return this;
  }

  build(): ResourcePolicy {
    return this.policy as ResourcePolicy;
  }
}

// Integration with existing RBAC system
class IntegratedAccessControl {
  constructor(
    private rbac: any, // Your existing RBAC system
    private policyEngine: ResourcePolicyEngine
  ) {}

  async checkAccess(
    userId: string, 
    action: string, 
    resourceId: string,
    context?: any
  ): Promise<boolean> {
    // First check RBAC permissions
    const rbacAllowed = await this.rbac.hasPermission(userId, action);
    if (!rbacAllowed) {
      return false; // RBAC denial takes precedence
    }

    // Then check resource-specific policies
    const request: AccessRequest = {
      principal: userId,
      action,
      resourceId,
      resourceArn: `arn:aws:service:region:account:resource/${resourceId}`,
      context
    };

    const result = await this.policyEngine.evaluateAccess(request);
    return result.allowed;
  }
}

// Example usage and test cases
async function demonstrateResourcePolicies() {
  const policyEngine = new ResourcePolicyEngine();

  // Create a storage bucket policy
  const bucketPolicy = PolicyBuilder
    .create(ResourceType.STORAGE_BUCKET, 'user-documents-bucket')
    .allowPrincipal('User', ['user-123', 'user-456'])
    .withAction(['storage:GetObject', 'storage:PutObject'])
    .withResource('arn:aws:s3:::user-documents-bucket/*')
    .withCondition('IpAddress', 'sourceIp', '192.168.1.0/24')
    .build();

  await policyEngine.attachPolicy('user-documents-bucket', bucketPolicy);

  // Create a deny policy for sensitive operations
  const denyPolicy = PolicyBuilder
    .create(ResourceType.STORAGE_BUCKET, 'user-documents-bucket')
    .denyPrincipal('User', ['user-789'])
    .withAction('storage:DeleteObject')
    .withResource('arn:aws:s3:::user-documents-bucket/sensitive/*')
    .build();

  await policyEngine.attachPolicy('user-documents-bucket', denyPolicy);

  // Test access requests
  const testRequests: AccessRequest[] = [
    {
      principal: 'user-123',
      action: 'storage:GetObject',
      resourceId: 'user-documents-bucket',
      resourceArn: 'arn:aws:s3:::user-documents-bucket/file.txt',
      context: { sourceIp: '192.168.1.100' }
    },
    {
      principal: 'user-789',
      action: 'storage:DeleteObject',
      resourceId: 'user-documents-bucket',
      resourceArn: 'arn:aws:s3:::user-documents-bucket/sensitive/secret.txt'
    }
  ];

  for (const request of testRequests) {
    const result = await policyEngine.evaluateAccess(request);
    console.log(`Access for ${request.principal} to ${request.action}: ${result.allowed ? 'ALLOWED' : 'DENIED'}`);
    if (result.reason) {
      console.log(`Reason: ${result.reason}`);
    }
  }
}

// Export the main components
export {
  ResourcePolicyEngine,
  PolicyBuilder,
  IntegratedAccessControl,
  ResourceType,
  type ResourcePolicy,
  type PolicyStatement,
  type AccessRequest,
  type AccessResult
};