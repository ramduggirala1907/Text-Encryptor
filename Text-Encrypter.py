
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

class EncryptionToolkit:
    def __init__(self):
        # Generate RSA key pair
        self.rsa_key = RSA.generate(2048)
        
    def aes_encrypt(self, plaintext: str) -> tuple:
        """
        Encrypt text using AES-256 in CBC mode
        Returns (encrypted_text, key, iv)
        """
        key = get_random_bytes(32)  # 256-bit key
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(plaintext.encode(), AES.block_size)
        encrypted_text = cipher.encrypt(padded_data)
        
        return (base64.b64encode(encrypted_text).decode('utf-8'),
                base64.b64encode(key).decode('utf-8'),
                base64.b64encode(cipher.iv).decode('utf-8'))

    def aes_decrypt(self, encrypted_text: str, key: str, iv: str) -> str:
        """Decrypt AES encrypted text"""
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)
        encrypted_text = base64.b64decode(encrypted_text)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_text)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        
        return unpadded_data.decode('utf-8')

    def des_encrypt(self, plaintext: str) -> tuple:
        """
        Encrypt text using DES in CBC mode
        Returns (encrypted_text, key, iv)
        """
        key = get_random_bytes(8)  # DES uses 64-bit key
        cipher = DES.new(key, DES.MODE_CBC)
        padded_data = pad(plaintext.encode(), DES.block_size)
        encrypted_text = cipher.encrypt(padded_data)
        
        return (base64.b64encode(encrypted_text).decode('utf-8'),
                base64.b64encode(key).decode('utf-8'),
                base64.b64encode(cipher.iv).decode('utf-8'))

    def des_decrypt(self, encrypted_text: str, key: str, iv: str) -> str:
        """Decrypt DES encrypted text"""
        key = base64.b64decode(key)
        iv = base64.b64decode(iv)
        encrypted_text = base64.b64decode(encrypted_text)
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_text)
        unpadded_data = unpad(decrypted_data, DES.block_size)
        
        return unpadded_data.decode('utf-8')

    def rsa_encrypt(self, plaintext: str) -> str:
        """
        Encrypt text using RSA with PKCS1_OAEP
        Returns base64-encoded encrypted text
        """
        cipher = PKCS1_OAEP.new(self.rsa_key.publickey())
        encrypted_text = cipher.encrypt(plaintext.encode())
        return base64.b64encode(encrypted_text).decode('utf-8')

    def rsa_decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt RSA encrypted text with PKCS1_OAEP
        """
        encrypted_text = base64.b64decode(encrypted_text)
        cipher = PKCS1_OAEP.new(self.rsa_key)
        decrypted_text = cipher.decrypt(encrypted_text)
        return decrypted_text.decode('utf-8')

    def sha256_hash(self, text: str) -> str:
        """Generate SHA-256 hash of text"""
        return hashlib.sha256(text.encode()).hexdigest()

    def sha512_hash(self, text: str) -> str:
        """Generate SHA-512 hash of text"""
        return hashlib.sha512(text.encode()).hexdigest()


def main():
    # Example usage
    toolkit = EncryptionToolkit()
    
    # Original text
    original_text = input("Enter the text to be encrypted: ")
    print(f"Original text: {original_text}\n")

    # AES encryption/decryption
    print("=== AES Encryption ===")
    encrypted_text, key, iv = toolkit.aes_encrypt(original_text)
    print(f"Encrypted (AES): {encrypted_text}")
    print("")
    
    # DES encryption/decryption
    print("=== DES Encryption ===")
    encrypted_text, key, iv = toolkit.des_encrypt(original_text)
    print(f"Encrypted (DES): {encrypted_text}")
    print("")
    

    # RSA encryption/decryption
    print("=== RSA Encryption ===")
    encrypted_text = toolkit.rsa_encrypt(original_text)
    print(f"Encrypted (RSA): {encrypted_text}")
    print("")
    

    # SHA hashing
    print("=== SHA Hashing ===")
    print(f"SHA-256: {toolkit.sha256_hash(original_text)}")
    print(f"SHA-512: {toolkit.sha512_hash(original_text)}")
    

if __name__ == "__main__":
    main()
