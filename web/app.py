from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
import json
from typing import Dict, List
from permissions.manager import PermissionsManager, Permission, Action

class WebApp:
    def __init__(self, permissions_manager: PermissionsManager, mdns_proxy=None):
        self.app = Flask(__name__, template_folder='../templates', static_folder='../static')
        CORS(self.app)
        self.permissions_manager = permissions_manager
        self.mdns_proxy = mdns_proxy
        self._setup_routes()
    
    def _setup_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/permissions', methods=['GET'])
        def get_permissions():
            permissions = []
            for i, perm in enumerate(self.permissions_manager.get_all_permissions()):
                permissions.append({
                    'id': i,
                    'client_ip': perm.client_ip,
                    'client_mac': perm.client_mac,
                    'service_types': perm.service_types,
                    'service_names': perm.service_names,
                    'action': perm.action.value,
                    'enabled': perm.enabled
                })
            
            return jsonify({
                'permissions': permissions,
                'defaults': {
                    'allow_read': self.permissions_manager.matrix.default_allow_read,
                    'allow_publish': self.permissions_manager.matrix.default_allow_publish
                }
            })
        
        @self.app.route('/api/permissions', methods=['POST'])
        def add_permission():
            data = request.get_json()
            
            try:
                permission = Permission(
                    client_ip=data['client_ip'],
                    client_mac=data.get('client_mac'),
                    service_types=data.get('service_types', []),
                    service_names=data.get('service_names', []),
                    action=Action(data['action']),
                    enabled=data.get('enabled', True)
                )
                
                self.permissions_manager.add_permission(permission)
                return jsonify({'success': True})
            
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 400
        
        @self.app.route('/api/permissions/<int:perm_id>', methods=['DELETE'])
        def delete_permission(perm_id):
            try:
                self.permissions_manager.remove_permission(perm_id)
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 400
        
        @self.app.route('/api/defaults', methods=['POST'])
        def set_defaults():
            data = request.get_json()
            
            try:
                self.permissions_manager.set_defaults(
                    data.get('allow_read', False),
                    data.get('allow_publish', False)
                )
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 400
        
        @self.app.route('/api/clients', methods=['GET'])
        def get_clients():
            if self.mdns_proxy:
                clients = []
                for client in self.mdns_proxy.get_active_clients():
                    clients.append({
                        'ip': client.ip,
                        'mac': client.mac
                    })
                return jsonify({'clients': clients})
            else:
                return jsonify({'clients': []})
        
        @self.app.route('/api/test-permission', methods=['POST'])
        def test_permission():
            data = request.get_json()
            
            try:
                result = self.permissions_manager.check_permission(
                    data['client_ip'],
                    data.get('client_mac'),
                    data['service_type'],
                    data['service_name'],
                    Action(data['action'])
                )
                return jsonify({'allowed': result})
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/services', methods=['GET'])
        def get_services():
            if self.mdns_proxy:
                services = []
                for service in self.mdns_proxy.get_discovered_services():
                    services.append({
                        'name': service.name,
                        'service_type': service.service_type,
                        'domain': service.domain,
                        'ip': service.ip,
                        'port': service.port,
                        'txt_records': service.txt_records,
                        'last_seen': service.last_seen,
                        'ttl': service.ttl
                    })
                return jsonify({'services': services})
            else:
                return jsonify({'services': []})
    
    def run(self, host='0.0.0.0', port=8080, debug=False):
        self.app.run(host=host, port=port, debug=debug)