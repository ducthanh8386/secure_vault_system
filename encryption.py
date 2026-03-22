"""
======================================
MODULE: encryption.py
Xử lý mã hóa/giải mã AES
======================================

Chức năng:
- Mã hóa dữ liệu bằng AES-256 (CBC mode)
- Giải mã dữ liệu
- Quản lý IV (Initialization Vector)

Tại sao dùng AES?
- AES là chuẩn mã hóa hiện đại, mạnh mẽ
- Được sử dụng rộng rãi trong thực tế
- 256-bit key = 2^256 độ khó tấn công
- CBC mode cung cấp bảo mật cao
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding # Thêm thư viện padding
from cryptography.hazmat.backends import default_backend
import os
from typing import Tuple

class AESEncryption:
    """Lớp xử lý AES encryption/decryption (Đã sửa lỗi padding và binary)"""
    
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"Key phải có 32 bytes, nhận {len(key)} bytes")
        self.key = key
        self.backend = default_backend()
    
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Mã hóa dữ liệu (nhận vào bytes, trả ra bytes)
        """
        # 1. Sinh IV ngẫu nhiên
        iv = os.urandom(16)
        
        # 2. Tạo đối tượng đệm (Padding) để đảm bảo dữ liệu chia hết cho 16 bytes
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # 3. Mã hóa dữ liệu đã đệm
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Giải mã dữ liệu (trả về bytes gốc)
        """
        # 1. Giải mã dữ liệu
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 2. Gỡ bỏ lớp đệm (Unpadding) để lấy lại dữ liệu gốc
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext

def test_encryption():
    """Test encryption đã cập nhật"""
    import hashlib
    key = hashlib.sha256(b"my_secret_password").digest() # Sinh key 32 bytes tạm để test
    aes = AESEncryption(key)
    
    # Test với chuỗi (cần chuyển sang bytes trước khi đưa vào)
    text = b"Hello, Secure Vault!"
    iv, ciphertext = aes.encrypt(text)
    decrypted = aes.decrypt(iv, ciphertext)
    print(f"Test Text: {text == decrypted}")
    
    # Test với độ dài lẻ (không chia hết cho 16)
    odd_text = b"12345"
    iv2, cipher2 = aes.encrypt(odd_text)
    print(f"Test Odd Length: {odd_text == aes.decrypt(iv2, cipher2)}")

if __name__ == "__main__":
    test_encryption()