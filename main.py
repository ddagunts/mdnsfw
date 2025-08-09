#!/usr/bin/env python3

import asyncio
import logging
import signal
import sys
import threading
from config import Config
from permissions.manager import PermissionsManager
from mdns.proxy import MDNSProxy
from web.app import WebApp

class MDNSFirewall:
    def __init__(self):
        self.config = Config.from_env()
        self.permissions_manager = PermissionsManager(self.config.permissions_file)
        self.mdns_proxy = None
        self.web_app = None
        self.running = False
        
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def start_web_app(self):
        self.web_app = WebApp(self.permissions_manager, self.mdns_proxy)
        
        def run_web_app():
            try:
                self.web_app.run(
                    host=self.config.web_host,
                    port=self.config.web_port,
                    debug=False
                )
            except Exception as e:
                self.logger.error(f"Failed to start web app: {e}")
                sys.exit(1)
        
        web_thread = threading.Thread(target=run_web_app, daemon=True)
        web_thread.start()
        self.logger.info(f"Web interface started on http://{self.config.web_host}:{self.config.web_port}")
    
    def setup_signal_handlers(self):
        def signal_handler(signum, frame):
            self.logger.info("Received shutdown signal")
            self.shutdown()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def shutdown(self):
        self.logger.info("Shutting down mDNS firewall...")
        self.running = False
        if self.mdns_proxy:
            self.mdns_proxy.stop()
    
    async def run(self):
        self.logger.info("Starting mDNS Firewall")
        self.logger.info(f"mDNS address: {self.config.mdns_address}:{self.config.mdns_port}")
        self.logger.info(f"Web interface: http://{self.config.web_host}:{self.config.web_port}")
        self.logger.info(f"Permissions file: {self.config.permissions_file}")
        
        self.setup_signal_handlers()
        
        # Initialize mDNS proxy first
        self.mdns_proxy = MDNSProxy(
            self.permissions_manager,
            self.config.mdns_address,
            self.config.mdns_port,
            self.config.services_storage_file,
            self.config
        )
        
        # Start web app with initialized proxy
        self.start_web_app()
        
        self.running = True
        
        try:
            await self.mdns_proxy.start()
        except Exception as e:
            self.logger.error(f"Failed to start mDNS proxy: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

def main():
    try:
        firewall = MDNSFirewall()
        asyncio.run(firewall.run())
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()