import hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
import base64
import json

class ProvenanceLedger:
    def __init__(self):
        # In a real scenario, this would be an immutable blockchain or database
        self.ledger = {}
        
    def record_provenance(self, doc_hash: str, signature: str, metadata: dict):
        self.ledger[doc_hash] = {
            "signature": signature,
            "metadata": metadata
        }
        
    def get_provenance(self, doc_hash: str):
        return self.ledger.get(doc_hash)

class CryptoNode:
    def __init__(self):
        # Generate a new ECDSA key pair for this node (simulating a DID)
        self.signing_key = SigningKey.generate(curve=SECP256k1)
        self.verifying_key = self.signing_key.get_verifying_key()
        self.ledger = ProvenanceLedger()
        
    def get_public_key_pem(self) -> str:
        return self.verifying_key.to_pem().decode('utf-8')
        
    def hash_content(self, content: str) -> str:
        """Create a SHA-256 hash of the content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
        
    def sign_hash(self, hash_hex: str) -> str:
        """Sign a hash using the node's private key."""
        hash_bytes = bytes.fromhex(hash_hex)
        signature = self.signing_key.sign_digest(
            hash_bytes,
            sigencode=sigencode_der
        )
        return base64.b64encode(signature).decode('utf-8')
        
    def verify_signature(self, hash_hex: str, signature_b64: str, public_key_pem: str) -> bool:
        """Verify that a signature is valid for a given hash and public key."""
        from ecdsa import VerifyingKey
        try:
            hash_bytes = bytes.fromhex(hash_hex)
            signature = base64.b64decode(signature_b64)
            vk = VerifyingKey.from_pem(public_key_pem)
            return vk.verify_digest(
                signature,
                hash_bytes,
                sigdecode=sigdecode_der
            )
        except Exception as e:
            return False

    def process_and_sign_chunk(self, chunk_text: str, source_metadata: dict):
        """Hashes the chunk, signs it, and records it on the ledger."""
        chunk_hash = self.hash_content(chunk_text)
        signature = self.sign_hash(chunk_hash)
        self.ledger.record_provenance(chunk_hash, signature, source_metadata)
        return chunk_hash, signature
