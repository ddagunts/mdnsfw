# mDNS Firewall

A Python-based mDNS reflector/proxy with firewall capabilities that allows administrators to control which clients can publish and read mDNS entries through a web-based management interface.
<img width="1342" height="932" alt="Screenshot 2025-08-09 at 07 38 25" src="https://github.com/user-attachments/assets/34897c78-e95e-43a5-be34-d3d130fd2b39" />
<img width="1328" height="949" alt="image" src="https://github.com/user-attachments/assets/4142df08-fe64-49df-a8d2-e58abf8f69dc" />



## Features

- **mDNS Proxy/Reflector**: Intercepts and filters mDNS traffic
- **Selective Permissions**: Control read/publish access per client and service
- **Web-based Admin UI**: Manage permissions through a user-friendly interface
- **Permissions Matrix**: Store permissions on disk for backup and persistence
- **Client Identification**: Track active clients by IP and MAC address
- **Service Filtering**: Filter by service types and service names with wildcard support

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python main.py
```

## Configuration

The application can be configured using environment variables:

- `MDNS_PORT`: mDNS port (default: 5353)
- `MDNS_ADDRESS`: mDNS multicast address (default: 224.0.0.251)
- `WEB_PORT`: Web interface port (default: 8080)
- `WEB_HOST`: Web interface host (default: 0.0.0.0)
- `PERMISSIONS_FILE`: Permissions storage file (default: permissions.yaml)
- `LOG_LEVEL`: Logging level (default: INFO)

## Usage

1. Start the application: `python main.py`
2. Open the web interface: `http://localhost:8080`
3. Configure default permissions and add specific rules
4. Monitor active clients and test permissions

## Permission Rules

Each permission rule consists of:
- **Client IP**: IP address of the client (use "*" for wildcard)
- **Client MAC**: MAC address (optional)
- **Service Types**: List of service types (e.g., "_http._tcp")
- **Service Names**: List of service names (e.g., "printer.local")
- **Action**: Either "read" or "publish"
- **Status**: Enabled or disabled

## Web Interface

The web interface provides:
- Default permission settings
- Add/remove permission rules
- View active clients
- Test permission scenarios
- Real-time permission management

## Security Notes

This is a defensive security tool designed to:
- Control mDNS traffic flow
- Prevent unauthorized service discovery
- Manage network service visibility
- Audit mDNS activity

Run with appropriate privileges to bind to the mDNS port (5353).
