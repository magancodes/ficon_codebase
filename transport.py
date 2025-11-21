import socket
import threading
import time
import struct
import random
import zlib
import queue

# --- Protocol Constants ---
# Header Format: ! (Network Endian)
# B (Version) B (Type) H (Flags) H (StreamID) I (Seq) I (Ack) H (PayloadLen) H (Checksum)
# Total Header Size: 1 + 1 + 2 + 2 + 4 + 4 + 2 + 2 = 18 Bytes
HEADER_FORMAT = '!BBHHIIHH'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Packet Types
PKT_DATA    = 0
PKT_ACK     = 1
PKT_SYN     = 2
PKT_SYN_ACK = 3
PKT_FIN     = 4

# Flags
FLAG_NONE = 0

# Settings
TIMEOUT = 2.0  # Seconds to wait for ACK
MAX_RETRIES = 3
BUFFER_SIZE = 65535

class ConnectionState:
    """
    Represents the state of a connection to a specific peer.
    """
    def __init__(self, peer_name, ip, port, transport, stream_id=0):
        self.peer_name = peer_name
        self.ip = ip
        self.port = port
        self.transport = transport
        
        # Ensure Stream ID fits in 2 bytes (0-65535)
        self.stream_id = stream_id & 0xFFFF
        
        self.seq_num = 0
        self.expected_seq = 0
        self.last_ack_received = -1
        self.connected = False
        self.handshake_complete = threading.Event()
        
        # Thread safety
        self.lock = threading.Lock()

    def start_handshake(self):
        """Initiates the 3-way handshake."""
        print(f"[Transport] Starting handshake with {self.peer_name}...")
        
        # Retrieve display name safely (Fix for AttributeError)
        my_name = getattr(self.transport.crypto, 'display_name', 'Unknown')
        my_key = self.transport.crypto.get_public_key_b64()
        
        # Payload: "MyName:MyPublicKey"
        payload = f"{my_name}:{my_key}".encode('utf-8')
        
        # Send SYN
        if self.transport._send_reliable(self, PKT_SYN, payload):
            print(f"[Transport] Handshake with {self.peer_name} successful.")
            self.connected = True
        else:
            print(f"[Transport] Handshake with {self.peer_name} failed (Timeout).")

class ReliableTransport:
    """
    Reliable UDP Transport Layer.
    Handles packetizing, retransmission, and connection state.
    """
    def __init__(self, crypto_layer, message_callback):
        self.crypto = crypto_layer
        self.message_callback = message_callback
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0)) # Bind to any available port
        self.listening_port = self.sock.getsockname()[1]
        
        self.running = False
        self.connections = {} # key: "ip:port", value: ConnectionState
        self.connections_by_name = {} # key: name, value: ConnectionState
        self.listen_thread = None

    def start_listening(self):
        """Starts the background thread to receive UDP packets."""
        self.running = True
        self.listen_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.listen_thread.start()
        print(f"[Transport] Listening on UDP port {self.listening_port}")

    def stop(self):
        """Stops the transport layer."""
        self.running = False
        self.sock.close()

    def connect(self, peer_name, ip, port, pkey_b64):
        """
        Initiates a connection to a peer.
        """
        addr_key = f"{ip}:{port}"
        if addr_key in self.connections:
            print(f"[Transport] Already connected to {peer_name}.")
            return

        # Generate a safe 16-bit Stream ID (1 to 65000)
        # This prevents the struct.error you were seeing
        stream_id = random.randint(1, 65000)

        conn = ConnectionState(peer_name, ip, port, self, stream_id)
        
        # Register connection
        self.connections[addr_key] = conn
        self.connections_by_name[peer_name] = conn
        
        # Start Handshake in a separate thread so we don't block the CLI
        threading.Thread(target=conn.start_handshake, daemon=True).start()

    def is_connected(self, peer_name):
        if peer_name in self.connections_by_name:
            return self.connections_by_name[peer_name].connected
        return False

    def send_message(self, peer_name, message):
        """Sends a text message to a connected peer."""
        if peer_name not in self.connections_by_name:
            print(f"[Transport] Error: Unknown peer {peer_name}")
            return

        conn = self.connections_by_name[peer_name]
        if not conn.connected:
            print(f"[Transport] Error: Not connected to {peer_name}")
            return

        # 1. Encrypt (assuming CryptoLayer has encrypt method)
        # We send the message as bytes
        msg_bytes = message.encode('utf-8')
        
        # TODO: Add actual encryption here if CryptoLayer supports it
        # encrypted = self.crypto.encrypt(msg_bytes, peer_public_key)
        # For now, sending plain text for the transport logic demo
        payload = msg_bytes

        # 2. Send reliably
        threading.Thread(target=self._send_reliable, args=(conn, PKT_DATA, payload), daemon=True).start()

    # --- Internal Methods ---

    def _send_reliable(self, conn, pkt_type, payload=b''):
        """
        Sends a packet and waits for an ACK. Retries if necessary.
        Returns True if ACK received, False otherwise.
        """
        seq = conn.seq_num
        # Prepare the packet
        packet = self._create_packet(pkt_type, seq, 0, conn.stream_id, payload)
        
        for attempt in range(MAX_RETRIES):
            self.sock.sendto(packet, (conn.ip, conn.port))
            
            # Wait for ACK (Simplified Stop-and-Wait)
            # In a real implementation, we'd use a condition variable or event
            start_time = time.time()
            while time.time() - start_time < TIMEOUT:
                if conn.last_ack_received >= seq:
                    conn.seq_num += 1
                    return True
                time.sleep(0.1)
            
            print(f"[Transport] Timeout, retrying ({attempt + 1}/{MAX_RETRIES})...")

        print(f"[Transport] Failed to send packet to {conn.peer_name}")
        return False

    def _send_ack(self, addr, stream_id, ack_num):
        """Sends a simple ACK packet."""
        packet = self._create_packet(PKT_ACK, 0, ack_num, stream_id, b'')
        self.sock.sendto(packet, addr)

    def _create_packet(self, pkt_type, seq, ack_num, stream_id, payload):
        """
        Creates the full binary packet (Header + Payload).
        """
        payload_len = len(payload)
        checksum = 0 # Calculate real checksum if needed
        
        # --- FIX: Generate Header Safely ---
        # We clamp values to ensure they fit in the struct
        header = self._create_header_safe(pkt_type, seq, ack_num, payload_len, checksum, stream_id)
        
        return header + payload

    def _create_header_safe(self, pkt_type, seq, ack_num, payload_len, checksum, stream_id, flags=0, version=1):
        """
        Creates the header with strict type enforcing to prevent struct.error.
        """
        # Enforce limits for 'H' (unsigned short, 2 bytes, max 65535)
        stream_id = int(stream_id) & 0xFFFF
        payload_len = int(payload_len) & 0xFFFF
        checksum = int(checksum) & 0xFFFF
        flags = int(flags) & 0xFFFF
        
        # Enforce limits for 'I' (unsigned int, 4 bytes)
        seq = int(seq) & 0xFFFFFFFF
        ack_num = int(ack_num) & 0xFFFFFFFF
        
        return struct.pack(HEADER_FORMAT, version, pkt_type, flags, stream_id, seq, ack_num, payload_len, checksum)

    def _receive_loop(self):
        """Main loop to handle incoming packets."""
        while self.running:
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                print(f"[Transport] Error in receive loop: {e}")

    def _handle_packet(self, data, addr):
        if len(data) < HEADER_SIZE:
            return # Invalid packet

        # Unpack Header
        header_bytes = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]
        
        try:
            # Unpack: Ver, Type, Flags, StreamID, Seq, Ack, Len, Cksum
            ver, pkt_type, flags, stream_id, seq, ack, p_len, cksum = struct.unpack(HEADER_FORMAT, header_bytes)
        except struct.error:
            return

        addr_key = f"{addr[0]}:{addr[1]}"

        # Handle ACK
        if pkt_type == PKT_ACK:
            if addr_key in self.connections:
                self.connections[addr_key].last_ack_received = ack
            return

        # Handle SYN (New Connection)
        if pkt_type == PKT_SYN:
            self._handle_syn(addr, stream_id, payload)
            # Send ACK for SYN
            self._send_ack(addr, stream_id, seq)
            return

        # Handle DATA
        if pkt_type == PKT_DATA:
            if addr_key in self.connections:
                conn = self.connections[addr_key]
                if seq == conn.expected_seq:
                    # Valid packet in order
                    conn.expected_seq += 1
                    try:
                        msg_text = payload.decode('utf-8')
                        self.message_callback(conn.peer_name, msg_text)
                    except:
                        pass
                # Always ACK data we receive
                self._send_ack(addr, stream_id, seq)

    def _handle_syn(self, addr, stream_id, payload):
        """Handles an incoming connection request."""
        try:
            # Payload is "Name:PublicKey"
            decoded = payload.decode('utf-8')
            if ":" in decoded:
                peer_name, peer_key = decoded.split(":", 1)
                
                addr_key = f"{addr[0]}:{addr[1]}"
                
                # If we don't know this peer, accept connection
                if addr_key not in self.connections:
                    print(f"[Transport] Incoming connection from {peer_name} ({addr[0]})")
                    conn = ConnectionState(peer_name, addr[0], addr[1], self, stream_id)
                    conn.connected = True # Established
                    conn.expected_seq = 1 # SYN consumes seq 0, next is 1
                    
                    self.connections[addr_key] = conn
                    self.connections_by_name[peer_name] = conn
        except Exception as e:
            print(f"[Transport] Error handling SYN: {e}")