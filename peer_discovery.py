import socket
import threading
import time
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
        self.listen_port = 0

    def start(self, update_callback, listen_port):
        self.is_running = True
        self.listen_port = listen_port
        
        # Start browsing
        self.listener = PeerListener(update_callback, self.display_name)
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self.listener)
        
        # Start advertising
        registration_thread = threading.Thread(target=self._register_service, daemon=True)
        registration_thread.start()
        
        print(f" [Discovery] Advertising service on port {self.listen_port}...")

    def stop(self):
        if self.is_running:
            self.is_running = False
            if self.service_info:
                self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            print(" [Discovery] Stopped.")

    def _get_best_ip(self):
        """
        Finds the best IP address to use, prioritizing LAN IPs (192.168.x.x)
        and avoiding virtual adapters (Docker, VMWare, etc).
        """
        # 1. Get all IP addresses associated with this machine's hostname
        ip_list = []
        try:
            hostname = socket.gethostname()
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            ip_list = socket.gethostbyname_ex(hostname)[2]
        except Exception:
            pass

        # 2. Priority 1: Standard Home/Office LAN IPs (192.168.x.x)
        for ip in ip_list:
            if ip.startswith("192.168."):
                return ip
        
        # 3. Priority 2: other Private IPs (10.x.x.x, 172.16-31.x.x)
        for ip in ip_list:
            if ip.startswith("10."):
                return ip
            if ip.startswith("172."):
                # Filter out Docker default (usually 172.17.x.x) if possible, 
                # but 172.16-31 are valid private ranges. 
                # We accept them if 192.168 wasn't found.
                return ip

        # 4. Fallback: Try the connection method (asks OS for default route)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 1)) # Doesn't send packet, just checks route
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            pass

        # 5. Last Resort
        return '127.0.0.1'

    def _register_service(self):
        port = self.listen_port 
        
        # Use smart IP detection
        ip_address_str = self._get_best_ip()
        
        print(f" [Discovery] Selected Network IP: {ip_address_str}")

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
        
        while self.is_running:
            time.sleep(1)


class PeerListener(ServiceListener):
    def __init__(self, update_callback, self_name):
        self.peers = {}
        self.update_callback = update_callback
        self.self_name = self_name
        self.zeroconf = Zeroconf()

    def _update_peers(self):
        filtered_peers = {name: info for name, info in self.peers.items() if name != self.self_name}
        self.update_callback(filtered_peers)

    def add_service(self, zc: Zeroconf, type_: str, name: str):
        info = zc.get_service_info(type_, name)
        if info: self._process_service_info(info)

    def update_service(self, zc: Zeroconf, type_: str, name: str):
        info = zc.get_service_info(type_, name)
        if info: self._process_service_info(info)

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
            
            if not info.addresses: return
                
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port

            if display_name and public_key and display_name != self.self_name:
                if display_name not in self.peers:
                    print(f" [Discovery] Peer found: {display_name} at {address}:{port}")
                self.peers[display_name] = (address, port, public_key)
                self._update_peers()
        except Exception as e:
            print(f" [Discovery] Error processing info: {e}")

    def _get_display_name_from_info_name(self, name: str) -> str:
        return name.split('._p2pchat.')[0]