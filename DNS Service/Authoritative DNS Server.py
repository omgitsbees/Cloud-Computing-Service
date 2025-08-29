import asyncio
import dns.message
import dns.rrset
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.flags
import dns.name
import dns.rcode
import sqlite3
import json
import logging
import uvicorn
import multiprocessing
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, constr
from enum import Enum
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("dns_service")

# Models
class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"

class RoutingPolicy(str, Enum):
    SIMPLE = "simple"
    WEIGHTED = "weighted"
    LATENCY = "latency"
    FAILOVER = "failover"
    GEOLOCATION = "geolocation"

class DNSRecord(BaseModel):
    name: constr(regex=r'^[a-zA-Z0-9.-]+$')
    type: RecordType
    ttl: int = 300
    values: List[str]
    routing_policy: RoutingPolicy = RoutingPolicy.SIMPLE
    weight: Optional[int] = None
    region: Optional[str] = None
    health_check_id: Optional[str] = None
    created_at: datetime = None
    updated_at: datetime = None

class Zone(BaseModel):
    name: constr(regex=r'^[a-zA-Z0-9.-]+$')
    records: Dict[str, List[DNSRecord]] = {}
    comment: Optional[str] = None
    created_at: datetime = None
    updated_at: datetime = None

# Storage Implementation
class DNSStorage:
    def __init__(self, db_path: str = "dns_records.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS zones (
                    name TEXT PRIMARY KEY,
                    records TEXT,
                    comment TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

    def create_zone(self, zone: Zone) -> Zone:
        zone.created_at = datetime.utcnow()
        zone.updated_at = zone.created_at
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO zones (name, records, comment, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (zone.name, json.dumps({}), zone.comment, zone.created_at.isoformat(), zone.updated_at.isoformat())
            )
        return zone

    def get_zone(self, name: str) -> Optional[Zone]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM zones WHERE name = ?", (name,))
            row = cursor.fetchone()
            
            if row:
                return Zone(
                    name=row[0],
                    records=json.loads(row[1]),
                    comment=row[2],
                    created_at=datetime.fromisoformat(row[3]),
                    updated_at=datetime.fromisoformat(row[4])
                )
        return None

    def add_record(self, zone_name: str, record: DNSRecord):
        zone = self.get_zone(zone_name)
        if not zone:
            raise ValueError(f"Zone {zone_name} not found")

        record.created_at = datetime.utcnow()
        record.updated_at = record.created_at
        
        if record.name not in zone.records:
            zone.records[record.name] = []
        zone.records[record.name].append(record)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE zones SET records = ?, updated_at = ? WHERE name = ?",
                (json.dumps(zone.records), datetime.utcnow().isoformat(), zone_name)
            )

# DNS Server Implementation
class AuthoritativeDNSServer:
    def __init__(self, storage: DNSStorage, host: str = "0.0.0.0", port: int = 53):
        self.storage = storage
        self.host = host
        self.port = port
        self.zones: Dict[str, Zone] = {}
        self._load_zones()

    def _load_zones(self):
        """Load zones from storage into memory"""
        # Implementation would load zones from storage
        pass

    async def handle_query(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        try:
            query = dns.message.from_wire(data)
            response = dns.message.make_response(query)
            
            if len(query.question) == 0:
                return response.to_wire()

            qname = str(query.question[0].name)
            qtype = query.question[0].rdtype

            zone_name = self._find_matching_zone(qname)
            if not zone_name:
                response.flags |= dns.flags.AA
                return response.to_wire()

            answers = self._get_matching_records(qname, qtype, zone_name)
            if answers:
                response.answer.extend(answers)
                response.flags |= dns.flags.AA

            return response.to_wire()

        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")
            return self._make_error_response(data)

    def _find_matching_zone(self, qname: str) -> Optional[str]:
        parts = qname.split('.')
        for i in range(len(parts)):
            possible_zone = '.'.join(parts[i:])
            if possible_zone in self.zones:
                return possible_zone
        return None

    def _get_matching_records(self, qname: str, qtype: int, zone_name: str) -> List[dns.rrset.RRset]:
        zone = self.zones[zone_name]
        if qname not in zone.records:
            return []

        records = zone.records[qname]
        matching_records = [r for r in records if r.type == RecordType(dns.rdatatype.to_text(qtype))]
        
        if not matching_records:
            return []

        rrset = dns.rrset.RRset(dns.name.from_text(qname), dns.rdataclass.IN, qtype)
        rrset.ttl = matching_records[0].ttl

        for record in matching_records:
            for value in record.values:
                rrset.add(dns.rdata.from_text(dns.rdataclass.IN, qtype, value))

        return [rrset]

    def _make_error_response(self, query_data: bytes) -> bytes:
        try:
            response = dns.message.make_response(dns.message.from_wire(query_data))
            response.set_rcode(dns.rcode.SERVFAIL)
            return response.to_wire()
        except:
            return b''

    async def start(self):
        loop = asyncio.get_event_loop()
        
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self.handle_query),
            local_addr=(self.host, self.port)
        )
        
        logger.info(f"DNS server listening on {self.host}:{self.port}")
        
        try:
            await asyncio.Event().wait()
        finally:
            transport.close()

class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, query_handler):
        self.query_handler = query_handler
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle_query(data, addr))

    async def _handle_query(self, data: bytes, addr: Tuple[str, int]):
        response = await self.query_handler(data, addr)
        if response:
            self.transport.sendto(response, addr)

# API Server Implementation
app = FastAPI(title="DNS Service API")
storage = DNSStorage()

@app.post("/zones", response_model=Zone)
async def create_zone(zone: Zone):
    try:
        return storage.create_zone(zone)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/zones/{name}", response_model=Zone)
async def get_zone(name: str):
    zone = storage.get_zone(name)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    return zone

@app.post("/zones/{zone_name}/records")
async def add_record(zone_name: str, record: DNSRecord):
    try:
        storage.add_record(zone_name, record)
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Main entry point
async def run_dns_server():
    storage = DNSStorage()
    server = AuthoritativeDNSServer(storage)
    await server.start()

def run_api_server():
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    # Start API server in a separate process
    api_process = multiprocessing.Process(target=run_api_server)
    api_process.start()

    # Run DNS server in main process
    asyncio.run(run_dns_server())