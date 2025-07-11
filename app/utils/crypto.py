import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Tuple, Union

class AESCipher:
    def __init__(self, key: str):
        """
        Initialize AES cipher with SHA-256 hashed key
        
        Args:
            key: Encryption key as string
        """
        self.key = hashlib.sha256(key.encode()).digest()
        
    def encrypt(self, data: str) -> bytes:
        """
        Encrypt data with AES-256-CBC
        
        Args:
            data: Plaintext to encrypt
            
        Returns:
            bytes: IV (16 bytes) + ciphertext
        """
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext
        
def decrypt(self, encrypted_data: bytes) -> Union[str, bytes]:
    """
    Decrypt AES-256-CBC encrypted data
    
    Args:
        encrypted_data: IV (16 bytes) + ciphertext
        
    Returns:
        str: Decrypted plaintext if successful
        bytes: Raw decrypted data if decoding fails
        
    Raises:
        ValueError: If decryption fails
    """
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted data too short to contain IV")
        
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
        
    cipher = AES.new(self.key, AES.MODE_CBC, iv)
    
    try:
        decrypted = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted, AES.block_size)
        
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext  # Return bytes if decoding fails
            
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def generate_key(length: int = 32) -> str:
    """
    Generate random encryption key
    
    Args:
        length: Length of key in bytes (default: 32)
        
    Returns:
        str: Hex representation of random bytes
    """
    if length < 16:
        raise ValueError("Key length should be at least 16 bytes")
    return get_random_bytes(length).hex()