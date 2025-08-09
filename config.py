import os
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Config:
    mdns_port: int = 5353
    mdns_address: str = "224.0.0.251"
    web_port: int = 8080
    web_host: str = "0.0.0.0"
    permissions_file: str = "permissions.yaml"
    services_storage_file: str = "data/services.json"
    log_level: str = "INFO"
    ip_blacklist: List[str] = field(default_factory=lambda: ["172.16.0.1", "169.254.0.0/16", "127.0.0.0/8"])
    
    @classmethod
    def from_env(cls):
        # Parse IP blacklist from environment variable
        blacklist_str = os.getenv("IP_BLACKLIST", "172.16.0.1,169.254.0.0/16,127.0.0.0/8")
        ip_blacklist = [ip.strip() for ip in blacklist_str.split(",") if ip.strip()]
        
        return cls(
            mdns_port=int(os.getenv("MDNS_PORT", 5353)),
            mdns_address=os.getenv("MDNS_ADDRESS", "224.0.0.251"),
            web_port=int(os.getenv("WEB_PORT", 8080)),
            web_host=os.getenv("WEB_HOST", "0.0.0.0"),
            permissions_file=os.getenv("PERMISSIONS_FILE", "permissions.yaml"),
            services_storage_file=os.getenv("SERVICES_STORAGE_FILE", "data/services.json"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            ip_blacklist=ip_blacklist
        )