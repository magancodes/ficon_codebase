import base64
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError

# Constants based on X25519 and XChaCha20-Poly1305
NONCE_SIZE = 24 # For XChaCha20

class CryptoLayer:
    """
    Encapsulates all cryptographic logic for key management,
    key exchange, and end-to-end encryption.
    """
    def __init__(self):
        # Generate long-term identity key pair (Ed25519)
        self._identity_signing_key = SigningKey.generate()
        self._identity_verify_key = self._identity_signing_key.verify_key

    def get_public_key_b64(self):
        """Returns the Base64-encoded public identity key."""
        return base64.b64encode(self._identity_verify_key.encode()).decode('utf-8')

    def sign_data(self, data):
        """Signs data with the long-term private identity key."""
        return self._identity_signing_key.sign(data)

    @staticmethod
    def verify_signature(public_key_b64, signed_data):
        """Verifies a signature using a public identity key."""
        try:
            verify_key = VerifyKey(base64.b64decode(public_key_b64))
            return verify_key.verify(signed_data)
        except (CryptoError, TypeError, ValueError):
            return None

    @staticmethod
    def generate_ephemeral_keypair():
        """Generates a new, single-use key pair for ECDH (X25519)."""
        return PrivateKey.generate()

    def perform_authenticated_key_exchange(self, peer_name, peer_pkey_b64, send_func, receive_func):
        """
        Performs the authenticated ECDH key exchange to establish a shared session key.
        Returns the shared symmetric key on success, None on failure.
        """
        print(f"[{peer_name}] Starting authenticated key exchange...")
        
        # 1. Generate our ephemeral key pair
        my_ephemeral_private_key = self.generate_ephemeral_keypair()
        my_ephemeral_public_key_bytes = my_ephemeral_private_key.public_key.encode()

        # 2. Send our ephemeral public key and receive theirs
        send_func(my_ephemeral_public_key_bytes)
        peer_ephemeral_public_key_bytes = receive_func()
        if not peer_ephemeral_public_key_bytes:
            print(f"[{peer_name}] Failed to receive peer's ephemeral key.")
            return None

        # 3. Create the transcript to be signed
        # A consistent order is crucial for the signature to match.
        # Here, we order by comparing the raw public key bytes.
        my_id_key_bytes = self._identity_verify_key.encode()
        peer_id_key_bytes = base64.b64decode(peer_pkey_b64)

        if my_id_key_bytes < peer_id_key_bytes:
            transcript = my_ephemeral_public_key_bytes + peer_ephemeral_public_key_bytes
        else:
            transcript = peer_ephemeral_public_key_bytes + my_ephemeral_public_key_bytes

        # 4. Sign the transcript and send the signature
        my_signature = self.sign_data(transcript)
        send_func(my_signature)

        # 5. Receive and verify their signature
        peer_signature = receive_func()
        if not peer_signature:
            print(f"[{peer_name}] Failed to receive peer's signature.")
            return None
            
        verified_transcript = self.verify_signature(peer_pkey_b64, peer_signature)
        if verified_transcript!= transcript:
            print(f"[{peer_name}] MITM ATTACK DETECTED! Signature verification failed.")
            return None

        print(f"[{peer_name}] Signature verified successfully.")

        # 6. Compute the shared secret key using our private key and their public key
        try:
            peer_ephemeral_public_key = my_ephemeral_private_key.public_key.__class__(peer_ephemeral_public_key_bytes)
            box = Box(my_ephemeral_private_key, peer_ephemeral_public_key)
            shared_key = box.shared_key()
            print(f"[{peer_name}] Secure session key established.")
            return shared_key
        except Exception as e:
            print(f"[{peer_name}] Error computing shared key: {e}")
            return None

    @staticmethod
    def encrypt_aead(key, plaintext, associated_data):
        """
        Encrypts and authenticates plaintext using XChaCha20-Poly1305.
        The header (associated_data) is authenticated but not encrypted.
        """
        box = SecretBox(key)
        nonce = random(NONCE_SIZE)
        ciphertext = box.encrypt(plaintext.encode('utf-8'), nonce, associated_data)
        # The nonce is prepended to the ciphertext for transmission
        return ciphertext

    @staticmethod
    def decrypt_aead(key, ciphertext, associated_data):
        """
        Verifies and decrypts ciphertext using XChaCha20-Poly1305.
        Returns the plaintext string on success, None on failure (e.g., bad signature).
        """
        box = SecretBox(key)
        try:
            plaintext_bytes = box.decrypt(ciphertext, associated_data)
            return plaintext_bytes.decode('utf-8')
        except CryptoError:
            # This occurs if the authentication tag is invalid.
            # The packet has been tampered with or is corrupted.
            return None