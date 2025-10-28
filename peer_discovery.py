import socket
import threading
import time
import base64
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

class PeerDiscovery:
    """
    Manages advertising our service and discovering other peers on the LAN.
    """
    def __init__(self, service_type, display_name, public_key):
        self.service_type = service_type
        self.display_name = display_name
        self.public_key_b64 = public_key
        self.zeroconf = Zeroconf()
        self.service_info = None
        self.listener = None
        self.browser = None
        self.is_running = False

    def start(self, update_callback):
        """Starts the discovery and registration process."""
        self.is_running = True
        
        # Start browsing for other peers
        self.listener = PeerListener(update_callback, self.display_name)
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self.listener)
        
        # Start advertising our own service
        # We need a thread because register_service is blocking
        registration_thread = threading.Thread(target=self._register_service, daemon=True)
        registration_thread.start()
        
        print(" Started browsing and advertising.")

    def stop(self):
        """Stops the discovery and registration process."""
        if self.is_running:
            self.is_running = False
            if self.service_info:
                self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            print(" Stopped.")

    def _register_service(self):
        """Registers this peer's service on the network."""
        # The port will be assigned by the transport layer. For now, we use a placeholder.
        # In a real app, the transport layer would be started first to get a port.
        # For this example, we'll assume a fixed port for simplicity of demonstration.
        # A better approach is to pass the actual listening port from the transport layer.
        port = 12345 # This should be the actual listening port of the transport layer.

        properties = {
            'txtvers': '1',
            'name': self.display_name.encode('utf-8'),
            'pkey': self.public_key_b64.encode('utf-8')
        }
        
        # Get local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_address_str = '127.0.0.1' # Default
        try:
            s.connect(('10.255.255.255', 1))
            # FIX: Get only the IP (index 0) from the getsockname() tuple
            ip_address_str = s.getsockname()[0]
        except Exception:
            # Could not connect, fall back to default
            pass
        finally:
            s.close()

        instance_name = f"{self.display_name}._p2pchat"
        full_service_name = f"{instance_name}.{self.service_type}"

        self.service_info = ServiceInfo(
            type_=self.service_type,
            name=full_service_name,
            # FIX: Pass the IP string, not the tuple
            addresses=[socket.inet_aton(ip_address_str)],
            port=port,
            properties=properties,
            server=f"{socket.gethostname()}.local."
        )

        self.zeroconf.register_service(self.service_info)
        print(f" Registered service '{full_service_name}' at {ip_address_str}:{port}")
        
        # Keep the registration alive
        while self.is_running:
            time.sleep(1)


class PeerListener(ServiceListener):
    """
    Listens for mDNS service announcements and maintains a list of peers.
    """
    def __init__(self, update_callback, self_name):
        self.peers = {}
        self.update_callback = update_callback
        self.self_name = self_name
        self.zeroconf = Zeroconf()

    def _update_peers(self):
        """Calls the callback with the current list of peers."""
        # Filter out our own service from the list
        filtered_peers = {name: info for name, info in self.peers.items() if name != self.self_name}
        self.update_callback(filtered_peers)

    def add_service(self, zc: Zeroconf, type_: str, name: str):
        """Called when a new service is discovered."""
        info = zc.get_service_info(type_, name)
        if info:
            self._process_service_info(info)

    def update_service(self, zc: Zeroconf, type_: str, name: str):
        """Called when a service is updated."""
        info = zc.get_service_info(type_, name)
        if info:
            self._process_service_info(info)

    def remove_service(self, zc: Zeroconf, type_: str, name: str):
        """Called when a service is removed."""
        display_name = self._get_display_name_from_info_name(name)
        if display_name in self.peers:
            del self.peers[display_name]
            print(f" Peer left: {display_name}")
            self._update_peers()

    def _process_service_info(self, info: ServiceInfo):
        """Extracts peer information and updates the peer list."""
        try:
            properties = {k.decode('utf-8'): v.decode('utf-8') for k, v in info.properties.items()}
            display_name = properties.get('name')
            public_key = properties.get('pkey')
            
            # FIX: info.addresses is a list, get the first one
            # Also, ensure info.addresses is not empty
            if not info.addresses:
                return # Can't connect without an address
                
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port

            if display_name and public_key and display_name != self.self_name:
                if display_name not in self.peers:
                    print(f" Peer found: {display_name} at {address}:{port}")
                # Update peer info regardless of whether they were new or not
                self.peers[display_name] = (address, port, public_key)
                self._update_peers()
        except Exception as e:
            print(f" Error processing service info: {e}")

    def _get_display_name_from_info_name(self, name: str) -> str:
        """Extracts the display name from the full service instance name."""
        # e.g., "Alice._p2pchat._lan-chat._udp.local." -> "Alice"
        return name.split('._p2pchat.')[0]

