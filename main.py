import threading
import time
import queue
from peer_discovery import PeerDiscovery
from transport import ReliableTransport
from crypto import CryptoLayer

# --- Configuration ---
SERVICE_TYPE = "_lan-chat._udp.local."
SERVICE_NAME_PREFIX = "P2PChat"

class ChatApplication:
    """
    The main application class that orchestrates all components.
    """
    def __init__(self, display_name):
        self.display_name = display_name
        self.crypto = CryptoLayer()
        
        # --- FIX 1: Attribute Error ---
        # The Transport layer looks for 'display_name' inside the crypto object 
        # during the handshake. We attach it here manually to satisfy that requirement.
        self.crypto.display_name = self.display_name 

        # Initialize Peer Discovery (but don't start it yet, we need the port first)
        self.peer_discovery = PeerDiscovery(
            service_type=SERVICE_TYPE,
            display_name=self.display_name,
            public_key=self.crypto.get_public_key_b64()
        )
        
        # Initialize Transport Layer
        self.transport = ReliableTransport(
            crypto_layer=self.crypto,
            message_callback=self.handle_incoming_message
        )
        
        self.ui_queue = queue.Queue()
        self.peers = {} # Discovered peers: {name: (ip, port, pkey)}

    def start(self):
        """Starts all services in the correct order to prevent port mismatch."""
        print("Starting P2P Chat Application...")
        print(f"Your Identity: {self.display_name}")
        print(f"Your Public Key (Fingerprint): {self.crypto.get_public_key_b64()[:16]}...")

        # --- FIX 2: Port Mismatch / Timeout Error ---
        # 1. Start the Transport layer FIRST. 
        #    This asks the OS for an available port (binding to port 0).
        self.transport.start_listening()
        
        # 2. Get the ACTUAL port the OS assigned to us.
        real_port = self.transport.listening_port
        print(f"[System] Transport listening on port {real_port}")

        # 3. Start Peer Discovery, passing the REAL port.
        #    This ensures we advertise the correct port to the network via mDNS.
        #    (Note: Requires the updated peer_discovery.py that accepts a port arg)
        self.peer_discovery.start(self.handle_peer_update, real_port)
        
        # 4. Start the command-line interface thread
        ui_thread = threading.Thread(target=self.run_cli, daemon=True)
        ui_thread.start()

        print("\nApplication started. Discovering peers...")
        print("Type 'help' for a list of commands.")

    def stop(self):
        """Stops all services gracefully."""
        print("\nShutting down...")
        self.peer_discovery.stop()
        self.transport.stop()
        print("Shutdown complete.")

    def handle_peer_update(self, updated_peers):
        """Callback for when the list of discovered peers changes."""
        self.peers = updated_peers
        self.ui_queue.put(("peer_update", self.peers))

    def handle_incoming_message(self, peer_name, message):
        """Callback for when a message is received from the transport layer."""
        self.ui_queue.put(("message", (peer_name, message)))

    def run_cli(self):
        """The main loop for the command-line user interface."""
        while True:
            # Check for updates from other threads (async messages)
            try:
                event_type, data = self.ui_queue.get_nowait()
                if event_type == "peer_update":
                    print("\n[SYSTEM] Peer list updated. Type 'peers' to see.")
                elif event_type == "message":
                    peer_name, message = data
                    print(f"\n[{peer_name}]: {message}")
                self._redisplay_prompt()
            except queue.Empty:
                pass

            # User Input Handling
            try:
                # Note: In a production app, we would use a non-blocking input method.
                # Here we use blocking input for simplicity.
                command = input("> ").strip()
                self.process_command(command)
            except (KeyboardInterrupt, EOFError):
                self.stop()
                break

    def process_command(self, command):
        """Processes user input from the CLI."""
        parts = command.split(" ", 2)
        
        # --- FIX 3: CLI Crash on Empty Input ---
        # Handle empty input (e.g. user just pressed Enter)
        if not parts or parts[0] == '':
            return 
        
        # Safe lowercasing of the command verb
        cmd = parts[0].lower()

        if cmd == "help":
            print("Commands:")
            print("  peers                - List discovered peers.")
            print("  connect <peer_name>  - Establish a secure connection with a peer.")
            print("  send <peer_name> <msg> - Send a message to a connected peer.")
            print("  exit                 - Quit the application.")
        
        elif cmd == "peers":
            if not self.peers:
                print("No peers found yet.")
            else:
                print("Discovered Peers:")
                for name, info in self.peers.items():
                    # info is tuple: (ip, port, pkey)
                    status = "Connected" if self.transport.is_connected(name) else "Disconnected"
                    # Display the IP and Port stored in discovery to verify they match
                    print(f"  - {name} [{info[0]}:{info[1]}] ({status})")
        
        elif cmd == "connect":
            if len(parts) < 2:
                print("Usage: connect <peer_name>")
                return
            peer_name = parts[1]
            if peer_name in self.peers:
                ip, port, pkey_b64 = self.peers[peer_name]
                print(f"Connecting to {peer_name} at {ip}:{port}...")
                self.transport.connect(peer_name, ip, port, pkey_b64)
            else:
                print(f"Error: Peer '{peer_name}' not found.")
        
        elif cmd == "send":
            if len(parts) < 3:
                print("Usage: send <peer_name> <message>")
                return
            peer_name, message = parts[1], parts[2]
            if self.transport.is_connected(peer_name):
                self.transport.send_message(peer_name, message)
                print(f"Message sent to {peer_name}.")
            else:
                print(f"Error: Not connected to '{peer_name}'. Use 'connect' first.")
        
        elif cmd == "exit":
            self.stop()
            import sys
            sys.exit(0)
        
        else:
            if command:
                print(f"Unknown command: '{command}'. Type 'help'.")

    def _redisplay_prompt(self):
        """Helper to redisplay the input prompt after printing async messages."""
        print("> ", end="", flush=True)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python main.py <YourDisplayName>")
        sys.exit(1)
    
    app = ChatApplication(display_name=sys.argv[1])
    try:
        app.start()
        # Keep the main thread alive to let daemon threads run
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        app.stop()