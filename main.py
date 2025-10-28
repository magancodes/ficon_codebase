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
        self.peer_discovery = PeerDiscovery(
            service_type=SERVICE_TYPE,
            display_name=self.display_name,
            public_key=self.crypto.get_public_key_b64()
        )
        self.transport = ReliableTransport(
            crypto_layer=self.crypto,
            message_callback=self.handle_incoming_message
        )
        self.ui_queue = queue.Queue()
        self.peers = {} # Discovered peers: {name: (ip, port, pkey)}

    def start(self):
        """Starts all services: discovery, transport, and UI."""
        print("Starting P2P Chat Application...")
        print(f"Your Identity: {self.display_name}")
        print(f"Your Public Key (Fingerprint): {self.crypto.get_public_key_b64()[:16]}...")

        # Start peer discovery
        self.peer_discovery.start(self.handle_peer_update)
        
        # Start the transport layer to listen for incoming connections
        self.transport.start_listening()

        # Start the command-line interface thread
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
            # Check for updates from other threads (e.g., new messages, peer list changes)
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

            # Non-blocking input check (conceptual)
            # In a real CLI, you'd use a library like `select` or `prompt_toolkit`
            # For simplicity, we use a blocking input here.
            try:
                command = input("> ").strip()
                self.process_command(command)
            except (KeyboardInterrupt, EOFError):
                self.stop()
                break

    def process_command(self, command):
        """Processes user input from the CLI."""
        parts = command.split(" ", 2)
        
        # --- START OF FIX ---
        # Handle empty input (user just pressed Enter)
        if not parts or parts[0] == '':
            return 
        
        # Get the first item (the command) and lowercase it.
        cmd = parts[0].lower()
        # --- END OF FIX ---

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
                    status = "Connected" if self.transport.is_connected(name) else "Disconnected"
                    print(f"  - {name} ({status})")
        elif cmd == "connect":
            if len(parts) < 2:
                print("Usage: connect <peer_name>")
                return
            peer_name = parts[1]
            if peer_name in self.peers:
                ip, port, pkey_b64 = self.peers[peer_name]
                print(f"Connecting to {peer_name} at {ip}:{port}...")
                self.transport.connect(peer_name, ip, port, pkey_b64)
                # Connection is asynchronous, success/failure will be logged by transport
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
            exit(0)
        else:
            # We check 'command' here to avoid printing "Unknown command: ''"
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

