import React, { useState } from 'react';
import { Server, DollarSign, TrendingDown, Clock, AlertCircle, CheckCircle, XCircle } from 'lucide-react';

const SpotReservedDesign = () => {
  const [activeTab, setActiveTab] = useState('overview');

  const architectureComponents = [
    {
      name: "Pricing Engine",
      description: "Dynamic spot price calculation based on supply/demand",
      tech: "Go + Redis",
      key: true
    },
    {
      name: "Instance Scheduler",
      description: "Allocation and interruption management",
      tech: "Go + PostgreSQL",
      key: true
    },
    {
      name: "Capacity Manager",
      description: "Tracks available compute capacity",
      tech: "Go + Redis + TimescaleDB",
      key: true
    },
    {
      name: "Billing Service",
      description: "Metering and cost calculation",
      tech: "Go + PostgreSQL",
      key: false
    },
    {
      name: "Interruption Predictor",
      description: "ML-based spot interruption forecasting",
      tech: "Python + TensorFlow",
      key: false
    }
  ];

  const spotFeatures = [
    "Dynamic pricing based on capacity",
    "2-minute interruption warnings",
    "Spot fleet management",
    "Hibernate/stop/terminate options",
    "Persistent block storage",
    "Spot instance pools"
  ];

  const reservedFeatures = [
    "1-year and 3-year terms",
    "Standard and convertible types",
    "Scheduled reserved instances",
    "Capacity reservations",
    "Regional vs zonal benefits",
    "Reserved instance marketplace"
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl border border-white/20 overflow-hidden">
          <div className="bg-gradient-to-r from-purple-600 to-blue-600 p-8">
            <div className="flex items-center gap-4">
              <Server className="w-12 h-12 text-white" />
              <div>
                <h1 className="text-3xl font-bold text-white">Spot & Reserved Instances</h1>
                <p className="text-purple-100 mt-2">Cost optimization through flexible pricing models</p>
              </div>
            </div>
          </div>

          <div className="border-b border-white/10">
            <div className="flex">
              {['overview', 'architecture', 'spot', 'reserved', 'implementation'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-6 py-4 font-medium transition-all ${
                    activeTab === tab
                      ? 'bg-white/20 text-white border-b-2 border-purple-400'
                      : 'text-gray-300 hover:bg-white/5'
                  }`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="p-8">
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-gradient-to-br from-green-500/20 to-green-600/20 p-6 rounded-xl border border-green-500/30">
                    <DollarSign className="w-10 h-10 text-green-400 mb-3" />
                    <h3 className="text-xl font-bold text-white mb-2">On-Demand</h3>
                    <p className="text-gray-300 text-sm">Standard pricing, no commitment, full control</p>
                    <div className="mt-4 text-2xl font-bold text-green-400">100%</div>
                    <div className="text-sm text-gray-400">Base price</div>
                  </div>
                  
                  <div className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 p-6 rounded-xl border border-blue-500/30">
                    <TrendingDown className="w-10 h-10 text-blue-400 mb-3" />
                    <h3 className="text-xl font-bold text-white mb-2">Spot Instances</h3>
                    <p className="text-gray-300 text-sm">Up to 90% discount, interruptible with 2-min warning</p>
                    <div className="mt-4 text-2xl font-bold text-blue-400">10-30%</div>
                    <div className="text-sm text-gray-400">Of on-demand price</div>
                  </div>
                  
                  <div className="bg-gradient-to-br from-purple-500/20 to-purple-600/20 p-6 rounded-xl border border-purple-500/30">
                    <Clock className="w-10 h-10 text-purple-400 mb-3" />
                    <h3 className="text-xl font-bold text-white mb-2">Reserved</h3>
                    <p className="text-gray-300 text-sm">1-3 year commitment, 30-70% savings</p>
                    <div className="mt-4 text-2xl font-bold text-purple-400">30-70%</div>
                    <div className="text-sm text-gray-400">Discount with commitment</div>
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Key Concepts</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-400 mt-1 flex-shrink-0" />
                      <div>
                        <div className="font-medium text-white">Spot Price Fluctuation</div>
                        <div className="text-sm text-gray-400">Prices change based on supply/demand in each availability zone</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-400 mt-1 flex-shrink-0" />
                      <div>
                        <div className="font-medium text-white">Interruption Handling</div>
                        <div className="text-sm text-gray-400">2-minute warning before spot instance termination</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-400 mt-1 flex-shrink-0" />
                      <div>
                        <div className="font-medium text-white">Reserved Instance Types</div>
                        <div className="text-sm text-gray-400">Standard (fixed type) and Convertible (flexible attributes)</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-400 mt-1 flex-shrink-0" />
                      <div>
                        <div className="font-medium text-white">Capacity Reservations</div>
                        <div className="text-sm text-gray-400">Reserve capacity without committing to specific instances</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'architecture' && (
              <div className="space-y-6">
                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">System Architecture</h3>
                  <div className="space-y-4">
                    {architectureComponents.map((component, idx) => (
                      <div key={idx} className={`flex items-start gap-4 p-4 rounded-lg ${component.key ? 'bg-purple-500/20 border border-purple-500/30' : 'bg-white/5'}`}>
                        <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg flex items-center justify-center flex-shrink-0">
                          {idx + 1}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-bold text-white">{component.name}</h4>
                            {component.key && <span className="px-2 py-1 bg-yellow-500/20 text-yellow-300 text-xs rounded">Core</span>}
                          </div>
                          <p className="text-gray-300 text-sm mt-1">{component.description}</p>
                          <div className="text-xs text-purple-300 mt-2 font-mono">{component.tech}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Data Flow</h3>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 text-gray-300">
                      <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm">1</div>
                      <div>User submits spot/reserved instance request</div>
                    </div>
                    <div className="flex items-center gap-3 text-gray-300">
                      <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm">2</div>
                      <div>Capacity Manager checks available resources</div>
                    </div>
                    <div className="flex items-center gap-3 text-gray-300">
                      <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm">3</div>
                      <div>Pricing Engine calculates current spot price</div>
                    </div>
                    <div className="flex items-center gap-3 text-gray-300">
                      <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm">4</div>
                      <div>Instance Scheduler allocates VM or queues request</div>
                    </div>
                    <div className="flex items-center gap-3 text-gray-300">
                      <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm">5</div>
                      <div>Monitoring system tracks usage and triggers interruptions if needed</div>
                    </div>
                    <div className="flex items-center gap-3 text-gray-300">
                      <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm">6</div>
                      <div>Billing Service meters usage and calculates costs</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'spot' && (
              <div className="space-y-6">
                <div className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 p-6 rounded-xl border border-blue-500/30">
                  <h3 className="text-xl font-bold text-white mb-4">Spot Instance Features</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {spotFeatures.map((feature, idx) => (
                      <div key={idx} className="flex items-center gap-3">
                        <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0" />
                        <span className="text-gray-200">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Spot Pricing Algorithm</h3>
                  <div className="bg-slate-900 p-4 rounded-lg font-mono text-sm text-gray-300 overflow-x-auto">
                    <pre>{`// Spot price calculation
spotPrice = basePrice * (
  demandMultiplier * 
  capacityMultiplier * 
  timeOfDayMultiplier *
  zoneMultiplier
)

where:
  demandMultiplier = requestQueue / capacity
  capacityMultiplier = 1 / (availableInstances / totalCapacity)
  timeOfDayMultiplier = peak hours factor (1.2x) or off-peak (0.8x)
  zoneMultiplier = zone-specific supply/demand ratio

Price updates: Every 5 minutes
Min price: 10% of on-demand
Max price: 90% of on-demand`}</pre>
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Interruption Strategy</h3>
                  <div className="space-y-3">
                    <div className="flex items-start gap-3">
                      <AlertCircle className="w-5 h-5 text-yellow-400 mt-1" />
                      <div>
                        <div className="font-medium text-white">2-Minute Warning</div>
                        <div className="text-sm text-gray-400">Send interruption notice via instance metadata</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <AlertCircle className="w-5 h-5 text-yellow-400 mt-1" />
                      <div>
                        <div className="font-medium text-white">Graceful Shutdown</div>
                        <div className="text-sm text-gray-400">Allow applications to save state and clean up</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <AlertCircle className="w-5 h-5 text-yellow-400 mt-1" />
                      <div>
                        <div className="font-medium text-white">Interruption Behavior</div>
                        <div className="text-sm text-gray-400">User-specified: stop, hibernate, or terminate</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'reserved' && (
              <div className="space-y-6">
                <div className="bg-gradient-to-br from-purple-500/20 to-purple-600/20 p-6 rounded-xl border border-purple-500/30">
                  <h3 className="text-xl font-bold text-white mb-4">Reserved Instance Features</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {reservedFeatures.map((feature, idx) => (
                      <div key={idx} className="flex items-center gap-3">
                        <CheckCircle className="w-5 h-5 text-purple-400 flex-shrink-0" />
                        <span className="text-gray-200">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                    <h4 className="font-bold text-white mb-3">Standard Reserved</h4>
                    <div className="space-y-2 text-sm text-gray-300">
                      <div className="flex justify-between">
                        <span>1-year, no upfront</span>
                        <span className="text-green-400">40% savings</span>
                      </div>
                      <div className="flex justify-between">
                        <span>1-year, partial upfront</span>
                        <span className="text-green-400">45% savings</span>
                      </div>
                      <div className="flex justify-between">
                        <span>1-year, all upfront</span>
                        <span className="text-green-400">50% savings</span>
                      </div>
                      <div className="flex justify-between">
                        <span>3-year, all upfront</span>
                        <span className="text-green-400">70% savings</span>
                      </div>
                    </div>
                    <div className="mt-4 pt-4 border-t border-white/10 text-sm text-gray-400">
                      Fixed instance type and size
                    </div>
                  </div>

                  <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                    <h4 className="font-bold text-white mb-3">Convertible Reserved</h4>
                    <div className="space-y-2 text-sm text-gray-300">
                      <div className="flex justify-between">
                        <span>1-year, no upfront</span>
                        <span className="text-green-400">31% savings</span>
                      </div>
                      <div className="flex justify-between">
                        <span>1-year, partial upfront</span>
                        <span className="text-green-400">35% savings</span>
                      </div>
                      <div className="flex justify-between">
                        <span>1-year, all upfront</span>
                        <span className="text-green-400">38% savings</span>
                      </div>
                      <div className="flex justify-between">
                        <span>3-year, all upfront</span>
                        <span className="text-green-400">54% savings</span>
                      </div>
                    </div>
                    <div className="mt-4 pt-4 border-t border-white/10 text-sm text-gray-400">
                      Can change instance attributes
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Reservation Attributes</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <div className="font-medium text-white mb-2">Instance Type</div>
                      <div className="text-gray-400">t2.micro, m5.large, c5.xlarge, etc.</div>
                    </div>
                    <div>
                      <div className="font-medium text-white mb-2">Platform</div>
                      <div className="text-gray-400">Linux, Windows, RHEL, SUSE</div>
                    </div>
                    <div>
                      <div className="font-medium text-white mb-2">Tenancy</div>
                      <div className="text-gray-400">Default, dedicated, host</div>
                    </div>
                    <div>
                      <div className="font-medium text-white mb-2">Region/Zone</div>
                      <div className="text-gray-400">Regional or zonal reservation</div>
                    </div>
                    <div>
                      <div className="font-medium text-white mb-2">Term</div>
                      <div className="text-gray-400">1 year or 3 years</div>
                    </div>
                    <div>
                      <div className="font-medium text-white mb-2">Payment</div>
                      <div className="text-gray-400">No, partial, or all upfront</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'implementation' && (
              <div className="space-y-6">
                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Database Schema</h3>
                  <div className="bg-slate-900 p-4 rounded-lg font-mono text-xs text-gray-300 overflow-x-auto">
                    <pre>{`-- Spot Instances
CREATE TABLE spot_requests (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  instance_type VARCHAR(50),
  max_price DECIMAL(10,4),
  availability_zone VARCHAR(50),
  status VARCHAR(20), -- pending, active, interrupted, fulfilled
  launch_specification JSONB,
  interruption_behavior VARCHAR(20), -- stop, hibernate, terminate
  created_at TIMESTAMP,
  fulfilled_at TIMESTAMP
);

CREATE TABLE spot_prices (
  instance_type VARCHAR(50),
  availability_zone VARCHAR(50),
  price DECIMAL(10,4),
  timestamp TIMESTAMP,
  PRIMARY KEY (instance_type, availability_zone, timestamp)
);

CREATE TABLE spot_interruptions (
  instance_id UUID,
  interrupt_time TIMESTAMP,
  warning_time TIMESTAMP,
  reason VARCHAR(100),
  PRIMARY KEY (instance_id, interrupt_time)
);

-- Reserved Instances
CREATE TABLE reserved_instances (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  instance_type VARCHAR(50),
  platform VARCHAR(50),
  tenancy VARCHAR(20),
  availability_zone VARCHAR(50),
  term_years INTEGER,
  payment_option VARCHAR(20), -- no_upfront, partial, all_upfront
  type VARCHAR(20), -- standard, convertible
  start_date TIMESTAMP,
  end_date TIMESTAMP,
  upfront_payment DECIMAL(10,2),
  hourly_rate DECIMAL(10,4),
  instance_count INTEGER,
  status VARCHAR(20) -- active, expired, terminated
);

CREATE TABLE capacity_reservations (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  instance_type VARCHAR(50),
  availability_zone VARCHAR(50),
  instance_count INTEGER,
  start_date TIMESTAMP,
  end_date TIMESTAMP,
  status VARCHAR(20)
);

-- Capacity Tracking
CREATE TABLE capacity_pools (
  availability_zone VARCHAR(50),
  instance_type VARCHAR(50),
  total_capacity INTEGER,
  available_capacity INTEGER,
  reserved_capacity INTEGER,
  spot_capacity INTEGER,
  last_updated TIMESTAMP,
  PRIMARY KEY (availability_zone, instance_type)
);`}</pre>
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">API Endpoints</h3>
                  <div className="space-y-3">
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-green-400">POST</span> /api/v1/spot/request - Create spot instance request
                    </div>
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-blue-400">GET</span> /api/v1/spot/prices - Get current spot prices
                    </div>
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-blue-400">GET</span> /api/v1/spot/history - Get spot price history
                    </div>
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-yellow-400">DELETE</span> /api/v1/spot/request/:id - Cancel spot request
                    </div>
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-green-400">POST</span> /api/v1/reserved/purchase - Purchase reserved instance
                    </div>
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-blue-400">GET</span> /api/v1/reserved/offerings - List available reservations
                    </div>
                    <div className="bg-slate-900 p-3 rounded font-mono text-xs text-gray-300">
                      <span className="text-green-400">POST</span> /api/v1/reserved/modify - Modify convertible RI
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 p-6 rounded-xl border border-white/10">
                  <h3 className="text-xl font-bold text-white mb-4">Implementation Steps</h3>
                  <div className="space-y-3">
                    {[
                      "Build capacity tracking system with real-time updates",
                      "Implement dynamic pricing engine with configurable algorithms",
                      "Create spot instance request queue and fulfillment logic",
                      "Build interruption notification system (metadata endpoint)",
                      "Implement reserved instance purchase and validation",
                      "Create billing integration for both pricing models",
                      "Build marketplace for selling/buying reserved instances",
                      "Add monitoring and alerting for capacity and pricing",
                      "Implement savings plans (alternative to RIs)",
                      "Create cost optimization recommendations engine"
                    ].map((step, idx) => (
                      <div key={idx} className="flex items-start gap-3">
                        <div className="w-6 h-6 bg-purple-500 rounded-full flex items-center justify-center text-white text-xs flex-shrink-0">
                          {idx + 1}
                        </div>
                        <div className="text-gray-300">{step}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SpotReservedDesign;