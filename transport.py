import socket
import threading
import time
import struct
import zlib
import queue
from collections import deque

# --- Protocol Header Definition (18 bytes) ---
# Version (1 B), PacketType (1 B), Flags (1 B), StreamID (1 B)
# SequenceNum (4 B), AckNum (4 B), PayloadLength (2 B), HeaderChecksum (4 B)
HEADER_FORMAT = "!BBBBIIHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Packet Types
PKT_DATA = 0x01
PKT_ACK = 0x02
PKT_SYN = 0x03
PKT_SYN_ACK = 0x04
PKT_FIN = 0x05
PKT_KEY_EX = 0x06 # Key Exchange

class ReliableTransport:
    """
    Manages UDP sockets, threads, and the logic for reliable, secure P2P connections.
    """
    def __init__(self, crypto_layer, message_callback, port=12345):
        self.crypto = crypto_layer
        self.message_callback = message_callback
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.is_listening = False
        self.connections = {} # {peer_name: ConnectionState}
        self.lock = threading.Lock()

    def start_listening(self):
        """Binds the socket and starts the main receiver thread."""
        self.sock.bind(('', self.port))
        self.is_listening = True
        receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        receiver_thread.start()
        print(f" Listening on UDP port {self.port}")

    def stop(self):
        """Stops listening and closes all connections."""
        self.is_listening = False
        # Gracefully close connections
        with self.lock:
            for conn in self.connections.values():
                conn.close()
        self.sock.close()
        print(" Stopped.")

    def connect(self, peer_name, ip, port, pkey_b64):
        """Initiates a connection to a peer."""
        with self.lock:
            if peer_name in self.connections:
                print(f" Already connected or connecting to {peer_name}.")
                return
            
            conn_state = ConnectionState(
                peer_name=peer_name,
                peer_addr=(ip, port),
                peer_pkey_b64=pkey_b64,
                sock=self.sock,
                crypto=self.crypto,
                message_callback=self.message_callback,
                is_initiator=True
            )
            self.connections[peer_name] = conn_state
        
        conn_state.start_handshake()

    def is_connected(self, peer_name):
        """Checks if a secure connection is established with a peer."""
        with self.lock:
            conn = self.connections.get(peer_name)
            return conn and conn.is_secure()

    def send_message(self, peer_name, message):
        """Sends an application-level message to a peer."""
        with self.lock:
            conn = self.connections.get(peer_name)
        if conn and conn.is_secure():
            conn.send_data(message.encode('utf-8'))
        else:
            print(f" Cannot send message: no secure connection to {peer_name}")

    def _receiver_loop(self):
        """The main loop that receives all incoming UDP packets."""
        while self.is_listening:
            try:
                data, addr = self.sock.recvfrom(65535)
                
                # Unpack header to determine where to route the packet
                if len(data) < HEADER_SIZE:
                    continue # Malformed packet
                
                header_bytes = data
                payload = data
                
                # Find the connection associated with this address
                conn_to_process = None
                with self.lock:
                    for conn in self.connections.values():
                        if conn.peer_addr == addr:
                            conn_to_process = conn
                            break
                
                if conn_to_process:
                    conn_to_process.handle_packet(header_bytes, payload)
                else:
                    # Potentially a new incoming connection (SYN packet)
                    self._handle_new_connection(header_bytes, payload, addr)

            except Exception as e:
                if self.is_listening:
                    print(f" Receiver error: {e}")

    def _handle_new_connection(self, header_bytes, payload, addr):
        """Handles a packet that might be initiating a new connection."""
        try:
            header = unpack_header(header_bytes)
            if header and header['type'] == PKT_SYN:
                # This is a new connection request.
                # In a real app, you'd look up the peer's info (name, pkey) from discovery.
                # For simplicity, we'll assume the payload of SYN contains this info.
                # SYN payload: "peer_name:pkey_b64"
                peer_name, pkey_b64 = payload.decode('utf-8').split(':', 1)
                
                print(f" Received new connection request from {peer_name} at {addr}")
                
                with self.lock:
                    if peer_name in self.connections:
                        return # Already handling this connection
                    
                    conn_state = ConnectionState(
                        peer_name=peer_name,
                        peer_addr=addr,
                        peer_pkey_b64=pkey_b64,
                        sock=self.sock,
                        crypto=self.crypto,
                        message_callback=self.message_callback,
                        is_initiator=False
                    )
                    self.connections[peer_name] = conn_state
                
                conn_state.handle_packet(header_bytes, payload)
        except Exception as e:
            print(f" Error handling new connection: {e}")


class ConnectionState:
    """
    Manages the state of a single P2P connection, including handshakes,
    security, and reliability.
    """
    #... (A full implementation of this class would be extensive)
    # This is a simplified conceptual implementation.
    def __init__(self, peer_name, peer_addr, peer_pkey_b64, sock, crypto, message_callback, is_initiator):
        self.peer_name = peer_name
        self.peer_addr = peer_addr
        self.peer_pkey_b64 = peer_pkey_b64
        self.sock = sock
        self.crypto = crypto
        self.message_callback = message_callback
        self.is_initiator = is_initiator
        
        self.state = "DISCONNECTED" # DISCONNECTED, CONNECTING, AUTHENTICATING, SECURED, CLOSED
        self.session_key = None
        self.send_seq = 0
        self.recv_seq = 0
        
        # For reliability (conceptual)
        self.send_buffer = deque()
        self.unacked_packets = {} # {seq: (packet, timestamp)}
        
        # For key exchange
        self.key_exchange_queue = queue.Queue()

    def is_secure(self):
        return self.state == "SECURED"

    def start_handshake(self):
        """Initiator starts the 3-way handshake."""
        if self.is_initiator:
            self.state = "CONNECTING"
            # SYN payload contains our identity for the receiver to look us up
            payload = f"{self.crypto.display_name}:{self.crypto.get_public_key_b64()}".encode('utf-8')
            self._send_packet(PKT_SYN, payload=payload)
            print(f"[{self.peer_name}] Sent SYN.")

    def handle_packet(self, header_bytes, payload):
        """Main packet processing logic for this connection."""
        header = unpack_header(header_bytes)
        if not header:
            return # Checksum failed

        # --- Connection Handshake Logic ---
        if self.state == "CONNECTING":
            if self.is_initiator and header['type'] == PKT_SYN_ACK:
                print(f"[{self.peer_name}] Received SYN-ACK.")
                self._send_packet(PKT_ACK) # Final ACK of 3-way handshake
                self._start_key_exchange()
            elif not self.is_initiator and header['type'] == PKT_SYN:
                print(f"[{self.peer_name}] Received SYN, sending SYN-ACK.")
                self._send_packet(PKT_SYN_ACK)
        
        elif self.state == "AUTHENTICATING":
            if header['type'] == PKT_KEY_EX:
                self.key_exchange_queue.put(payload)

        elif self.state == "SECURED":
            if header['type'] == PKT_DATA:
                # Decrypt and process data
                plaintext = self.crypto.decrypt_aead(self.session_key, payload, header_bytes)
                if plaintext:
                    self.message_callback(self.peer_name, plaintext)
                    # Send ACK for the data packet
                    self._send_packet(PKT_ACK, ack_num=header['seq'] + 1)
                else:
                    print(f"[{self.peer_name}] Decryption failed! Packet dropped.")
            elif header['type'] == PKT_ACK:
                # Handle acknowledgment for our sent data (reliability logic)
                pass

    def _start_key_exchange(self):
        """Starts the authenticated key exchange in a separate thread."""
        self.state = "AUTHENTICATING"
        print(f"[{self.peer_name}] Transport established. Starting key exchange...")
        
        def key_ex_thread():
            def send_key_data(data):
                self._send_packet(PKT_KEY_EX, payload=data)
            
            def receive_key_data():
                try:
                    return self.key_exchange_queue.get(timeout=10)
                except queue.Empty:
                    return None

            key = self.crypto.perform_authenticated_key_exchange(
                self.peer_name, self.peer_pkey_b64, send_key_data, receive_key_data
            )
            if key:
                self.session_key = key
                self.state = "SECURED"
                print(f"[{self.peer_name}] Connection is now SECURE.")
            else:
                print(f"[{self.peer_name}] Key exchange FAILED. Closing connection.")
                self.close()

        threading.Thread(target=key_ex_thread, daemon=True).start()

    def send_data(self, data_bytes):
        """Encrypts and sends application data."""
        header_for_ad = create_header(PKT_DATA, seq=self.send_seq)
        encrypted_payload = self.crypto.encrypt_aead(self.session_key, data_bytes.decode('utf-8'), header_for_ad)
        self._send_packet(PKT_DATA, payload=encrypted_payload, seq=self.send_seq)
        self.send_seq += 1

    def _send_packet(self, pkt_type, payload=b'', seq=0, ack_num=0):
        """Constructs and sends a packet over the UDP socket."""
        header_bytes = create_header(pkt_type, seq=seq, ack_num=ack_num, payload_len=len(payload))
        self.sock.sendto(header_bytes + payload, self.peer_addr)

    def close(self):
        self.state = "CLOSED"
        # Send FIN packet, etc.

# --- Header Utility Functions ---

def create_header(pkt_type, flags=0, stream_id=0, seq=0, ack_num=0, payload_len=0):
    """Creates a packed protocol header."""
    version = 1
    # Pack without checksum first
    header_no_sum = struct.pack(HEADER_FORMAT[:-1], version, pkt_type, flags, stream_id, seq, ack_num, payload_len)
    checksum = zlib.crc32(header_no_sum)
    return struct.pack(HEADER_FORMAT, version, pkt_type, flags, stream_id, seq, ack_num, payload_len, checksum)

def unpack_header(header_bytes):
    """Unpacks a protocol header and verifies its checksum."""
    try:
        header_data = struct.unpack(HEADER_FORMAT, header_bytes)
        received_checksum = header_data[-1]
        
        header_no_sum = header_bytes[:-4] # All but the checksum field
        calculated_checksum = zlib.crc32(header_no_sum)
        
        if received_checksum!= calculated_checksum:
            print(" Checksum mismatch! Packet corrupted.")
            return None
            
        return {
            'version': header_data, 'type': header_data[1], 'flags': header_data[2],
            'stream_id': header_data[3], 'seq': header_data[4], 'ack': header_data[5],
            'len': header_data[6]
        }
    except struct.error:
        return None