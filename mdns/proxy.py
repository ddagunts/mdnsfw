import asyncio
import socket
import struct
import logging
import time
import json
import os
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from zeroconf import DNSRecord, DNSQuestion, current_time_millis
from zeroconf.const import _TYPE_A, _TYPE_PTR, _TYPE_SRV, _TYPE_TXT, _CLASS_IN
from permissions.manager import PermissionsManager, Action
from config import Config

@dataclass
class ClientInfo:
    ip: str
    mac: Optional[str] = None

@dataclass
class ServiceInfo:
    name: str
    service_type: str
    domain: str = "local."
    ip: Optional[str] = None
    port: Optional[int] = None
    txt_records: Dict[str, str] = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)
    ttl: int = 120
    source_ip: Optional[str] = None  # Track which client IP announced this service

class MDNSProxy:
    def __init__(self, permissions_manager: PermissionsManager, 
                 mdns_address: str = "224.0.0.251", mdns_port: int = 5353,
                 services_storage_file: str = "data/services.json", config: Config = None):
        self.permissions_manager = permissions_manager
        self.mdns_address = mdns_address
        self.mdns_port = mdns_port
        self.services_storage_file = services_storage_file
        self.config = config or Config()
        self.clients: Dict[str, ClientInfo] = {}
        self.services: Dict[str, ServiceInfo] = {}  # service_name -> ServiceInfo
        self.logger = logging.getLogger(__name__)
        
        self.sock = None
        self.running = False
        
        # Load persisted services on initialization
        self._load_services()
    
    def _is_ip_blacklisted(self, ip: str) -> bool:
        """Check if an IP address is in the blacklist"""
        if not ip or not self.config.ip_blacklist:
            return False
        
        try:
            ip_addr = ipaddress.ip_address(ip)
            for blacklist_entry in self.config.ip_blacklist:
                try:
                    if '/' in blacklist_entry:
                        # Network/CIDR notation
                        if ip_addr in ipaddress.ip_network(blacklist_entry, strict=False):
                            return True
                    else:
                        # Single IP address
                        if ip_addr == ipaddress.ip_address(blacklist_entry):
                            return True
                except (ipaddress.AddressValueError, ValueError) as e:
                    self.logger.warning(f"Invalid blacklist entry '{blacklist_entry}': {e}")
                    continue
        except (ipaddress.AddressValueError, ValueError) as e:
            self.logger.warning(f"Invalid IP address '{ip}': {e}")
            return False
        
        return False
    
    def _load_services(self):
        """Load services from persistent storage"""
        try:
            if os.path.exists(self.services_storage_file):
                with open(self.services_storage_file, 'r') as f:
                    data = json.load(f)
                    
                for service_data in data.get('services', []):
                    service = ServiceInfo(
                        name=service_data['name'],
                        service_type=self._extract_service_type(service_data['name']),
                        domain=service_data.get('domain', 'local.'),
                        ip=service_data.get('ip'),
                        port=service_data.get('port'),
                        txt_records=service_data.get('txt_records', {}),
                        last_seen=service_data.get('last_seen', time.time()),
                        ttl=service_data.get('ttl', 120),
                        source_ip=service_data.get('source_ip')
                    )
                    self.services[service.name] = service
                
                self.logger.info(f"Loaded {len(self.services)} services from storage")
            else:
                self.logger.info("No existing services storage file found")
        except Exception as e:
            self.logger.error(f"Error loading services from storage: {e}")
    
    def _save_services(self):
        """Save services to persistent storage"""
        try:
            # Ensure the data directory exists
            os.makedirs(os.path.dirname(self.services_storage_file), exist_ok=True)
            
            # Convert services to serializable format
            services_data = []
            for service in self.services.values():
                services_data.append(asdict(service))
            
            data = {
                'services': services_data,
                'last_updated': time.time()
            }
            
            with open(self.services_storage_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.debug(f"Saved {len(self.services)} services to storage")
        except Exception as e:
            self.logger.error(f"Error saving services to storage: {e}")
    
    async def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Add multicast socket options
        try:
            # Allow multiple sockets to bind to the same multicast address
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            # SO_REUSEPORT not available on all systems
            pass
        
        try:
            self.sock.bind(('', self.mdns_port))
            self.logger.info(f"Successfully bound to port {self.mdns_port}")
        except OSError as e:
            self.logger.error(f"Failed to bind to port {self.mdns_port}: {e}")
            return
        
        # Join multicast group - try multiple approaches for better compatibility
        try:
            # Method 1: Join on INADDR_ANY (standard approach)
            mreq = struct.pack("4sl", socket.inet_aton(self.mdns_address), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.logger.info(f"Joined multicast group {self.mdns_address} on INADDR_ANY")
            
            # Method 2: Try to join on specific local IPs (improved multicast reception)
            import subprocess
            try:
                # Get local IP addresses using ip command fallback
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    local_ips = result.stdout.strip().split()
                    for local_ip in local_ips:
                        if not local_ip.startswith('127.') and '::' not in local_ip:
                            try:
                                mreq2 = struct.pack("4s4s", socket.inet_aton(self.mdns_address), socket.inet_aton(local_ip))
                                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq2)
                                self.logger.info(f"Joined multicast group {self.mdns_address} on IP {local_ip}")
                            except Exception as e:
                                self.logger.debug(f"Could not join multicast on IP {local_ip}: {e}")
            except Exception as e:
                self.logger.debug(f"Could not get local IPs: {e}")
                
        except OSError as e:
            self.logger.error(f"Failed to join multicast group: {e}")
            return
        
        self.sock.setblocking(False)
        
        self.running = True
        self.logger.info(f"mDNS proxy started on {self.mdns_address}:{self.mdns_port}")
        self.logger.info("Waiting for mDNS packets...")
        
        packet_count = 0
        while self.running:
            try:
                await self._handle_packet()
                packet_count += 1
                if packet_count % 10 == 0:
                    self.logger.info(f"Processed {packet_count} packets so far")
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                self.logger.error(f"Error handling packet: {e}")
                await asyncio.sleep(0.1)
    
    async def _handle_packet(self):
        try:
            data, addr = self.sock.recvfrom(4096)
            client_ip = addr[0]
            
            self.logger.debug(f"Received mDNS packet from {client_ip}, size: {len(data)} bytes")
            
            if client_ip not in self.clients:
                self.clients[client_ip] = ClientInfo(ip=client_ip)
                self.logger.debug(f"New client discovered: {client_ip}")
            
            try:
                # Fix the parsing - use zeroconf's DNSIncoming class 
                from zeroconf import DNSIncoming
                dns_record = DNSIncoming(data)
                
                await self._process_dns_record(dns_record, client_ip)
            except Exception as e:
                self.logger.debug(f"Failed to parse DNS record from {client_ip}: {e}")
        
        except socket.error as e:
            if e.errno == 11:  # EAGAIN - no data available (normal for non-blocking sockets)
                await asyncio.sleep(0.1)
                return  # Don't count this as a processed packet
            else:
                self.logger.debug(f"Socket error {e.errno}: {e}")
                raise  # Re-raise other socket errors
        except Exception as e:
            self.logger.error(f"Unexpected error in packet handler: {e}")
            raise  # Re-raise to be caught by the main loop
    
    async def _process_dns_record(self, record: DNSRecord, client_ip: str):
        client = self.clients.get(client_ip)
        if not client:
            return
        
        try:
            # Try to access questions
            questions = []
            if hasattr(record, 'questions'):
                q_attr = getattr(record, 'questions')
                questions = q_attr() if callable(q_attr) else q_attr
            
            # Try to access answers 
            answers = []
            if hasattr(record, 'answers'):
                a_attr = getattr(record, 'answers')
                answers = a_attr() if callable(a_attr) else a_attr
                
            # Try to access other record types that contain service details
            authorities = []
            additionals = []
            if hasattr(record, 'authorities'):
                auth_attr = getattr(record, 'authorities', [])
                authorities = auth_attr() if callable(auth_attr) else auth_attr
            if hasattr(record, 'additionals'):
                add_attr = getattr(record, 'additionals', [])
                additionals = add_attr() if callable(add_attr) else add_attr
                
            self.logger.debug(f"Found {len(questions)} questions, {len(answers)} answers, {len(authorities)} authorities, {len(additionals)} additionals")
            
            # Log when we actually find response records
            if answers or authorities or additionals:
                self.logger.info(f"Processing response with {len(answers)} answers, {len(authorities)} authorities, {len(additionals)} additionals")
                # Log details about source IP for better tracking
                self.logger.debug(f"Response from client IP: {client_ip}")
            
            if questions:
                await self._handle_queries(record, client)
            
            # Check all types of response records for service details
            all_response_records = answers + authorities + additionals
            if all_response_records:
                await self._handle_responses(record, client)
                
        except Exception as e:
            self.logger.debug(f"Error processing DNS record: {e}")
    
    async def _handle_queries(self, record: DNSRecord, client: ClientInfo):
        questions = []
        if hasattr(record, 'questions'):
            q_attr = getattr(record, 'questions')
            questions = q_attr() if callable(q_attr) else q_attr
        
        for question in questions:
            service_name = question.name.lower()
            service_type = self._extract_service_type(service_name)
            
            # Only handle permissions and forwarding for queries - no service discovery
            if self.permissions_manager.check_permission(
                client.ip, client.mac, service_type, service_name, Action.READ):
                await self._forward_query(record, client)
                self.logger.info(f"Allowed query from {client.ip} for {service_name}")
            else:
                self.logger.info(f"Blocked query from {client.ip} for {service_name}")
    
    async def _handle_responses(self, record: DNSRecord, client: ClientInfo):
        # Access all response record types safely
        answers = []
        if hasattr(record, 'answers'):
            a_attr = getattr(record, 'answers')
            answers = a_attr() if callable(a_attr) else a_attr
            
        authorities = []
        if hasattr(record, 'authorities'):
            auth_attr = getattr(record, 'authorities')
            authorities = auth_attr() if callable(auth_attr) else auth_attr
            
        additionals = []
        if hasattr(record, 'additionals'):
            add_attr = getattr(record, 'additionals')
            additionals = add_attr() if callable(add_attr) else add_attr
            
        all_records = answers + authorities + additionals
        
        self.logger.info(f"Response handler processing {len(all_records)} total records")
        
        # Check permissions BEFORE learning services
        has_publish_permission = False
        for rr in all_records:
            service_name = rr.name.lower()
            service_type = self._extract_service_type(service_name)
            
            if self.permissions_manager.check_permission(
                client.ip, client.mac, service_type, service_name, Action.PUBLISH):
                has_publish_permission = True
                self.logger.info(f"Allowed publication from {client.ip} for {service_name}")
                break
            else:
                self.logger.warning(f"Blocked publication attempt from {client.ip} for {service_name} (type: {service_type})")
        
        # Only learn services and forward if client has publish permissions
        if has_publish_permission:
            await self._learn_services_from_records(all_records, client)
            await self._forward_response(record, client)
        else:
            self.logger.warning(f"Unauthorized client {client.ip} attempted to publish services - all records blocked")
    
    def _extract_service_type(self, name: str) -> str:
        parts = name.split('.')
        # Remove empty parts and 'local' domain
        parts = [p for p in parts if p and p != 'local']
        
        # Find the protocol part (_tcp or _udp)
        for i, part in enumerate(parts):
            if part in ['_tcp', '_udp']:
                # Find the service type (the part before _tcp/_udp)
                if i > 0:
                    return f"{parts[i-1]}.{part}"
                break
        
        # Fallback: look for common service type patterns
        for part in parts:
            if part.startswith('_') and not part.endswith('_tcp') and not part.endswith('_udp'):
                # Find the protocol that follows
                idx = parts.index(part)
                if idx + 1 < len(parts) and parts[idx + 1] in ['_tcp', '_udp']:
                    return f"{part}.{parts[idx + 1]}"
        
        return name
    
    async def _learn_services_from_records(self, records: List, client: ClientInfo):
        """Learn about services from DNS records - only called after permission validation"""
        self.logger.debug(f"Learning from {len(records)} DNS records from authorized client {client.ip}")
        for rr in records:
            try:
                self.logger.debug(f"Processing record: {rr.name} type={rr.type} from client {client.ip}")
                if rr.type == _TYPE_PTR:
                    await self._learn_from_ptr_record(rr, client)
                elif rr.type == _TYPE_SRV:
                    await self._learn_from_srv_record(rr, client)
                elif rr.type == _TYPE_A:
                    await self._learn_from_a_record(rr, client)
                elif rr.type == _TYPE_TXT:
                    await self._learn_from_txt_record(rr, client)
                else:
                    self.logger.debug(f"Unhandled record type {rr.type} for {rr.name}")
            except Exception as e:
                self.logger.error(f"Error learning from record {rr.name}: {e}")
                import traceback
                self.logger.debug(f"Traceback: {traceback.format_exc()}")
    
    async def _learn_from_ptr_record(self, rr, client: ClientInfo):
        """Learn service from PTR record"""
        # Check if client IP is blacklisted
        if self._is_ip_blacklisted(client.ip):
            self.logger.info(f"Ignoring PTR record from blacklisted client IP: {client.ip}")
            return
        
        # Defense-in-depth: Double-check publish permission
        service_type = rr.name.lower()
        if not self.permissions_manager.check_permission(
            client.ip, client.mac, service_type, service_type, Action.PUBLISH):
            self.logger.warning(f"PTR record blocked - client {client.ip} lacks permission for {service_type}")
            return
            
        service_type = rr.name.lower()
        try:
            # Different ways DNSPointer data can be accessed
            if hasattr(rr, 'alias'):
                service_name = str(rr.alias).lower()
            elif hasattr(rr, 'rdata') and rr.rdata:
                service_name = str(rr.rdata).lower()
            elif hasattr(rr, 'data'):
                service_name = str(rr.data).lower()
            else:
                service_name = str(rr).lower()
        except AttributeError:
            self.logger.debug(f"Could not extract service name from PTR record: {rr}")
            return
        
        self.logger.debug(f"PTR record: {service_type} -> {service_name}")
        
        if service_name not in self.services:
            self.services[service_name] = ServiceInfo(
                name=service_name,
                service_type=service_type,
                ttl=rr.ttl,
                source_ip=client.ip
            )
            self.logger.info(f"New service discovered: {service_name}")
            self._save_services()  # Save when new service is discovered
        else:
            self.services[service_name].last_seen = time.time()
            self.services[service_name].ttl = rr.ttl
            self.logger.debug(f"Updated existing service: {service_name}")
            self._save_services()  # Save when service is updated
    
    async def _learn_from_srv_record(self, rr, client: ClientInfo):
        """Learn service details from SRV record"""
        # Check if client IP is blacklisted
        if self._is_ip_blacklisted(client.ip):
            self.logger.info(f"Ignoring SRV record from blacklisted client IP: {client.ip}")
            return
        
        # Defense-in-depth: Double-check publish permission
        service_name = rr.name.lower()
        service_type = self._extract_service_type(service_name)
        if not self.permissions_manager.check_permission(
            client.ip, client.mac, service_type, service_name, Action.PUBLISH):
            self.logger.warning(f"SRV record blocked - client {client.ip} lacks permission for {service_name}")
            return
            
        service_name = rr.name.lower()
        port = None
        target = None
        
        try:
            if hasattr(rr, 'rdata') and rr.rdata:
                port = getattr(rr.rdata, 'port', None)
                target = getattr(rr.rdata, 'server', None) or getattr(rr.rdata, 'target', None)
            elif hasattr(rr, 'port'):
                port = rr.port
            elif hasattr(rr, 'target'):
                target = rr.target
        except AttributeError:
            self.logger.debug(f"Could not extract SRV data from record: {rr}")
        
        self.logger.debug(f"SRV record for {service_name}, port: {port}, target: {target}")
        
        if service_name not in self.services:
            self.services[service_name] = ServiceInfo(
                name=service_name,
                service_type=self._extract_service_type(service_name),
                port=port,
                ttl=rr.ttl,
                source_ip=client.ip
            )
            self.logger.info(f"New service from SRV: {service_name} (port {port})")
            self._save_services()  # Save when new service is discovered
        else:
            if port:
                self.services[service_name].port = port
                self.logger.info(f"Updated port for {service_name}: {port}")
            self.services[service_name].last_seen = time.time()
            self.services[service_name].ttl = rr.ttl
            self._save_services()  # Save when service is updated
    
    async def _learn_from_a_record(self, rr, client: ClientInfo):
        """Learn IP address from A record"""
        # Check if client IP is blacklisted
        if self._is_ip_blacklisted(client.ip):
            self.logger.info(f"Ignoring A record from blacklisted client IP: {client.ip}")
            return
        
        # Defense-in-depth: Double-check publish permission for hostname
        hostname = rr.name.lower()
        service_type = self._extract_service_type(hostname)
        if not self.permissions_manager.check_permission(
            client.ip, client.mac, service_type, hostname, Action.PUBLISH):
            self.logger.warning(f"A record blocked - client {client.ip} lacks permission for {hostname}")
            return
            
        hostname = rr.name.lower()
        ip = None
        
        try:
            if hasattr(rr, 'rdata') and rr.rdata:
                # Handle different types of rdata representations
                rdata = rr.rdata
                if hasattr(rdata, 'address'):
                    # Direct address attribute
                    ip = str(rdata.address)
                elif hasattr(rdata, 'data') and isinstance(rdata.data, bytes) and len(rdata.data) == 4:
                    # Raw 4-byte IP address - convert to dotted decimal
                    import struct
                    ip = socket.inet_ntoa(rdata.data)
                elif hasattr(rdata, 'data') and isinstance(rdata.data, (list, tuple)) and len(rdata.data) == 4:
                    # IP as list/tuple of 4 integers
                    ip = '.'.join(str(b) for b in rdata.data)
                else:
                    # Try string conversion as fallback
                    ip_str = str(rdata)
                    # Check if it looks like a bytestring representation
                    if ip_str.startswith("b'") and ip_str.endswith("'"):
                        # This is a bytestring representation - try to decode it safely
                        try:
                            # Remove b' and ' wrapper, then handle escape sequences
                            hex_content = ip_str[2:-1]
                            if '\\x' in hex_content:
                                # Parse hex escape sequences manually
                                byte_values = []
                                parts = hex_content.split('\\x')[1:]  # Skip the first empty part
                                for part in parts[:4]:  # Only take first 4 bytes for IPv4
                                    if len(part) >= 2:
                                        byte_val = int(part[:2], 16)
                                        byte_values.append(byte_val)
                                if len(byte_values) == 4:
                                    ip = '.'.join(str(b) for b in byte_values)
                                else:
                                    ip = ip_str
                            else:
                                ip = ip_str
                        except (ValueError, IndexError) as e:
                            self.logger.debug(f"Could not parse bytestring IP representation: {e}")
                            ip = ip_str
                    else:
                        ip = ip_str
            elif hasattr(rr, 'address'):
                address = rr.address
                if isinstance(address, bytes) and len(address) == 4:
                    ip = socket.inet_ntoa(address)
                else:
                    ip = str(address)
            elif hasattr(rr, 'data'):
                data = rr.data
                if isinstance(data, bytes) and len(data) == 4:
                    ip = socket.inet_ntoa(data)
                else:
                    ip = str(data)
        except AttributeError:
            self.logger.debug(f"Could not extract IP from A record: {rr}")
        except Exception as e:
            self.logger.debug(f"Error processing A record IP: {e}")
        
        self.logger.debug(f"A record for {hostname}, IP: {ip}")
        
        if not ip:
            return
        
        # Check if IP is blacklisted
        if self._is_ip_blacklisted(ip):
            self.logger.info(f"Ignoring service advertisement from blacklisted IP: {ip} for {hostname}")
            return
            
        # Find services that might be associated with this hostname
        updated = False
        for service_name, service in self.services.items():
            # More comprehensive hostname matching
            hostname_base = hostname.replace('.local.', '').replace('.local', '')
            service_base = service_name.replace('.local.', '').replace('.local', '')
            
            # Extract the instance name part from service names
            service_instance = service_name.split('.')[0] if '.' in service_name else service_name
            hostname_instance = hostname.split('.')[0] if '.' in hostname else hostname
            
            # Check various matching patterns
            if (hostname == service_name or 
                hostname_base == service_base or
                hostname_instance == service_instance or
                hostname in service_name or 
                service_name in hostname or
                hostname_base in service_base or
                service_base in hostname_base):
                
                if service.ip != ip:
                    service.ip = ip
                    self.logger.info(f"Updated IP for {service_name}: {ip}")
                    updated = True
                service.last_seen = time.time()
        
        # Also check if this might be a new service hostname
        if not updated:
            # Create a potential service entry for standalone hostnames
            if '._tcp.' in hostname or '._udp.' in hostname:
                if hostname not in self.services:
                    self.services[hostname] = ServiceInfo(
                        name=hostname,
                        service_type=self._extract_service_type(hostname),
                        ip=ip,
                        ttl=rr.ttl,
                        source_ip=client.ip
                    )
                    self.logger.info(f"New service from A record: {hostname} (IP {ip})")
                    updated = True
        
        if updated:
            self._save_services()  # Save when service is updated
    
    async def _learn_from_txt_record(self, rr, client: ClientInfo):
        """Learn service metadata from TXT record"""
        # Check if client IP is blacklisted
        if self._is_ip_blacklisted(client.ip):
            self.logger.info(f"Ignoring TXT record from blacklisted client IP: {client.ip}")
            return
        
        # Defense-in-depth: Double-check publish permission
        service_name = rr.name.lower()
        service_type = self._extract_service_type(service_name)
        if not self.permissions_manager.check_permission(
            client.ip, client.mac, service_type, service_name, Action.PUBLISH):
            self.logger.warning(f"TXT record blocked - client {client.ip} lacks permission for {service_name}")
            return
            
        service_name = rr.name.lower()
        
        new_service = service_name not in self.services
        
        if new_service:
            self.services[service_name] = ServiceInfo(
                name=service_name,
                service_type=self._extract_service_type(service_name),
                ttl=rr.ttl,
                source_ip=client.ip
            )
        
        # Parse TXT record data with multiple approaches
        txt_data = {}
        try:
            # Try different ways to extract TXT data
            if hasattr(rr, 'rdata') and rr.rdata:
                rdata = rr.rdata
                
                # Method 1: Check for 'data' attribute (list of bytes)
                if hasattr(rdata, 'data') and rdata.data:
                    for txt_entry in rdata.data:
                        try:
                            if isinstance(txt_entry, bytes):
                                txt_str = txt_entry.decode('utf-8', errors='replace')
                            else:
                                txt_str = str(txt_entry)
                            
                            if '=' in txt_str:
                                key, value = txt_str.split('=', 1)
                                txt_data[key] = value
                            else:
                                txt_data[txt_str] = ""
                        except Exception as decode_e:
                            self.logger.debug(f"Error decoding TXT entry {txt_entry}: {decode_e}")
                
                # Method 2: Check for 'text' attribute (some implementations)
                elif hasattr(rdata, 'text') and rdata.text:
                    for txt_entry in rdata.text:
                        try:
                            txt_str = txt_entry if isinstance(txt_entry, str) else txt_entry.decode('utf-8', errors='replace')
                            if '=' in txt_str:
                                key, value = txt_str.split('=', 1)
                                txt_data[key] = value
                            else:
                                txt_data[txt_str] = ""
                        except Exception as decode_e:
                            self.logger.debug(f"Error decoding TXT text entry {txt_entry}: {decode_e}")
                
                # Method 3: Try to convert rdata directly to string and parse
                elif rdata:
                    try:
                        rdata_str = str(rdata)
                        # Some implementations return quoted strings
                        if rdata_str.startswith('"') and rdata_str.endswith('"'):
                            rdata_str = rdata_str[1:-1]
                        
                        # Split by common delimiters and parse
                        entries = rdata_str.split('\x00') if '\x00' in rdata_str else [rdata_str]
                        for entry in entries:
                            if entry:
                                if '=' in entry:
                                    key, value = entry.split('=', 1)
                                    txt_data[key] = value
                                else:
                                    txt_data[entry] = ""
                    except Exception as str_e:
                        self.logger.debug(f"Error converting rdata to string: {str_e}")
                        
        except Exception as e:
            self.logger.debug(f"Error parsing TXT record for {service_name}: {e}")
        
        if txt_data:
            self.services[service_name].txt_records.update(txt_data)
            self.logger.info(f"Updated TXT records for {service_name}: {txt_data}")
        else:
            self.logger.debug(f"No TXT data found for {service_name} (rdata: {getattr(rr, 'rdata', 'None')})")
            
        self.services[service_name].last_seen = time.time()
        self.services[service_name].ttl = rr.ttl
        
        # Save services when new service or when TXT records are updated
        self._save_services()
        
        if new_service:
            self.logger.info(f"New service from TXT: {service_name}")
    
    async def _forward_query(self, record: DNSRecord, client: ClientInfo):
        try:
            # Use the original packet data for forwarding instead of repacking
            data = getattr(record, 'data', None)
            if data:
                for client_ip, other_client in self.clients.items():
                    if client_ip != client.ip:
                        self.sock.sendto(data, (client_ip, self.mdns_port))
            else:
                self.logger.debug("No packet data available for forwarding query")
        except Exception as e:
            self.logger.error(f"Error forwarding query: {e}")
    
    async def _forward_response(self, record: DNSRecord, client: ClientInfo):
        try:
            # Use the original packet data for forwarding instead of repacking
            data = getattr(record, 'data', None)
            if data:
                self.sock.sendto(data, (self.mdns_address, self.mdns_port))
            else:
                self.logger.debug("No packet data available for forwarding response")
        except Exception as e:
            self.logger.error(f"Error forwarding response: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.logger.info("mDNS proxy stopped")
    
    def get_active_clients(self) -> List[ClientInfo]:
        return list(self.clients.values())
    
    def get_discovered_services(self) -> List[ServiceInfo]:
        """Get all discovered services"""
        current_time = time.time()
        active_services = []
        
        # Remove expired services and return active ones
        expired_services = []
        for service_name, service in self.services.items():
            if current_time - service.last_seen > service.ttl:
                expired_services.append(service_name)
            else:
                active_services.append(service)
        
        # Clean up expired services
        if expired_services:
            for service_name in expired_services:
                del self.services[service_name]
                self.logger.debug(f"Removed expired service: {service_name}")
            self._save_services()  # Save after removing expired services
        
        return active_services
    
    def get_services_by_type(self, service_type: str) -> List[ServiceInfo]:
        """Get services filtered by type"""
        services = self.get_discovered_services()
        return [s for s in services if service_type.lower() in s.service_type.lower()]
    
    def get_service_by_name(self, service_name: str) -> Optional[ServiceInfo]:
        """Get a specific service by name"""
        self.get_discovered_services()  # Clean up expired services
        return self.services.get(service_name.lower())