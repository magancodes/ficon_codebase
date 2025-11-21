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
        self.listen_port = 0  # Will be set when start() is called

    def start(self, update_callback, listen_port):
        """
        Starts the discovery and registration process.
        Args:
            update_callback: Function to call when peers change.
            listen_port: The actual UDP port the Transport layer is listening on.
        """
        self.is_running = True
        self.listen_port = listen_port  # Store the real port
        
        # Start browsing for other peers
        self.listener = PeerListener(update_callback, self.display_name)
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self.listener)
        
        # Start advertising our own service
        registration_thread = threading.Thread(target=self._register_service, daemon=True)
        registration_thread.start()
        
        print(f" [Discovery] Advertising service on port {self.listen_port}...")

    def stop(self):
        """Stops the discovery and registration process."""
        if self.is_running:
            self.is_running = False
            if self.service_info:
                self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            print(" [Discovery] Stopped.")

    def _get_best_ip(self):
        """
        Robustly attempts to find the LAN IP address.
        Works even without internet access or gateway.
        """
        # Method 1: Try connecting to a pseudo-private IP. 
        # This doesn't send packets but checks routing table for the best interface.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            pass

        # Method 2: Hostname resolution (Good for Windows isolated LANs)
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            pass
            
        # Fallback
        return '127.0.0.1'

    def _register_service(self):
        """Registers this peer's service on the network."""
        
        # Use the real port passed from Transport Layer
        port = self.listen_port 
        
        # Use robust IP detection
        ip_address_str = self._get_best_ip()

        properties = {
            'txtvers': '1',
            'name': self.display_name.encode('utf-8'),
            'pkey': self.public_key_b64.encode('utf-8')
        }
        
        instance_name = f"{self.display_name}._p2pchat"
        full_service_name = f"{instance_name}.{self.service_type}"

        self.service_info = ServiceInfo(
            type_=self.service_type,
            name=full_service_name,
            addresses=[socket.inet_aton(ip_address_str)],
            port=port,
            properties=properties,
            server=f"{socket.gethostname()}.local."
        )

        try:
            self.zeroconf.register_service(self.service_info)
            print(f" [Discovery] Registered as '{self.display_name}' at {ip_address_str}:{port}")
        except Exception as e:
            print(f" [Discovery] Failed to register service: {e}")
        
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
        info = zc.get_service_info(type_, name)
        if info:
            self._process_service_info(info)

    def update_service(self, zc: Zeroconf, type_: str, name: str):
        info = zc.get_service_info(type_, name)
        if info:
            self._process_service_info(info)

    def remove_service(self, zc: Zeroconf, type_: str, name: str):
        display_name = self._get_display_name_from_info_name(name)
        if display_name in self.peers:
            del self.peers[display_name]
            print(f" [Discovery] Peer left: {display_name}")
            self._update_peers()

    def _process_service_info(self, info: ServiceInfo):
        try:
            properties = {k.decode('utf-8'): v.decode('utf-8') for k, v in info.properties.items()}
            display_name = properties.get('name')
            public_key = properties.get('pkey')
            
            if not info.addresses:
                return
                
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port

            if display_name and public_key and display_name != self.self_name:
                if display_name not in self.peers:
                    print(f" [Discovery] Peer found: {display_name} at {address}:{port}")
                # Update peer info regardless of whether they were new or not
                self.peers[display_name] = (address, port, public_key)
                self._update_peers()
        except Exception as e:
            print(f" [Discovery] Error processing info: {e}")

    def _get_display_name_from_info_name(self, name: str) -> str:
        """Extracts the display name from the full service instance name."""
        # e.g., "Alice._p2pchat._lan-chat._udp.local." -> "Alice"
        return name.split('._p2pchat.')[0]