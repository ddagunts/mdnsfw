import yaml
import os
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class Action(Enum):
    PUBLISH = "publish"
    READ = "read"

@dataclass
class Permission:
    client_ip: str
    client_mac: Optional[str]
    service_types: List[str]
    service_names: List[str]
    action: Action
    enabled: bool = True

@dataclass
class PermissionsMatrix:
    permissions: List[Permission]
    default_allow_read: bool = False
    default_allow_publish: bool = False

class PermissionsManager:
    def __init__(self, permissions_file: str = "permissions.yaml"):
        self.permissions_file = permissions_file
        self.matrix = self._load_permissions()
    
    def _load_permissions(self) -> PermissionsMatrix:
        if not os.path.exists(self.permissions_file):
            return PermissionsMatrix(permissions=[], default_allow_read=False, default_allow_publish=False)
        
        try:
            with open(self.permissions_file, 'r') as f:
                data = yaml.safe_load(f)
                if not data:
                    return PermissionsMatrix(permissions=[], default_allow_read=False, default_allow_publish=False)
                
                permissions = []
                for perm_data in data.get('permissions', []):
                    permissions.append(Permission(
                        client_ip=perm_data['client_ip'],
                        client_mac=perm_data.get('client_mac'),
                        service_types=perm_data.get('service_types', []),
                        service_names=perm_data.get('service_names', []),
                        action=Action(perm_data['action']),
                        enabled=perm_data.get('enabled', True)
                    ))
                
                return PermissionsMatrix(
                    permissions=permissions,
                    default_allow_read=data.get('default_allow_read', False),
                    default_allow_publish=data.get('default_allow_publish', False)
                )
        except Exception as e:
            print(f"Error loading permissions: {e}")
            return PermissionsMatrix(permissions=[], default_allow_read=False, default_allow_publish=False)
    
    def save_permissions(self):
        data = {
            'default_allow_read': self.matrix.default_allow_read,
            'default_allow_publish': self.matrix.default_allow_publish,
            'permissions': []
        }
        
        for perm in self.matrix.permissions:
            data['permissions'].append(asdict(perm))
        
        with open(self.permissions_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
    
    def check_permission(self, client_ip: str, client_mac: Optional[str], 
                        service_type: str, service_name: str, action: Action) -> bool:
        for perm in self.matrix.permissions:
            if not perm.enabled or perm.action != action:
                continue
            
            if perm.client_ip != "*" and perm.client_ip != client_ip:
                continue
            
            if perm.client_mac and client_mac and perm.client_mac != client_mac:
                continue
            
            if perm.service_types and "*" not in perm.service_types and service_type not in perm.service_types:
                continue
            
            if perm.service_names and "*" not in perm.service_names and service_name not in perm.service_names:
                continue
            
            return True
        
        if action == Action.READ:
            return self.matrix.default_allow_read
        elif action == Action.PUBLISH:
            return self.matrix.default_allow_publish
        
        return False
    
    def add_permission(self, permission: Permission):
        self.matrix.permissions.append(permission)
        self.save_permissions()
    
    def remove_permission(self, index: int):
        if 0 <= index < len(self.matrix.permissions):
            del self.matrix.permissions[index]
            self.save_permissions()
    
    def get_all_permissions(self) -> List[Permission]:
        return self.matrix.permissions
    
    def set_defaults(self, allow_read: bool, allow_publish: bool):
        self.matrix.default_allow_read = allow_read
        self.matrix.default_allow_publish = allow_publish
        self.save_permissions()