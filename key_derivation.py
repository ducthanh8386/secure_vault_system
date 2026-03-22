"""
======================================
MODULE: key_derivation.py
Sinh AES key từ password
======================================

Chức năng:
- Sinh AES key (256-bit) từ password user
- Dùng PBKDF2 để làm chậm quá trình (ngăn brute force)

Tại sao không dùng password trực tiếp?
- Password là string, có thể < 32 bytes
- PBKDF2 mở rộng key + làm chậm quá trình tính toán
- Ngăn chặn brute force attack:
  * Nếu hash password = mô phỏng trong 1ms
  * PBKDF2 với 100,000 iterations = 100ms
  * Tấn công sẽ lâu hơn 100x

PBKDF2 là gì?
- Password-Based Key Derivation Function 2
- Standard NIST (chính phủ Mỹ)
- Công thức: KDF(password, salt, iterations, output_length)
- Quá trình: hash(password+salt) 100,000 lần
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os


class KeyDerivation:
    """Lớp sinh AES key từ password"""
    
    # Cấu hình PBKDF2
    ITERATIONS = 100000  # 100k iterations (thường 100-200k)
    SALT_LENGTH = 16     # Salt length (bytes)
    OUTPUT_LENGTH = 32   # 32 bytes = 256 bits (cho AES-256)
    
    @staticmethod
    def generate_salt() -> bytes:
        """
        Sinh salt ngẫu nhiên cho PBKDF2
        
        Returns:
            bytes: Salt (16 bytes)
        """
        return os.urandom(KeyDerivation.SALT_LENGTH)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Sinh AES key từ password + salt
        
        Args:
            password (str): Mật khẩu của user
            salt (bytes): Salt ngẫu nhiên
        
        Returns:
            bytes: AES key (32 bytes = 256 bits)
        
        Chi tiết:
            - Dùng PBKDF2 với SHA-256
            - 100,000 iterations
            - Output 32 bytes
        
        Quá trình:
            password = "MyPassword123"
            salt = 16 random bytes
            key = PBKDF2(password, salt, iterations=100k, length=32)
            
            → key dùng để encrypt/decrypt dữ liệu của user
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KeyDerivation.OUTPUT_LENGTH,
            salt=salt,
            iterations=KeyDerivation.ITERATIONS,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key
    
    @staticmethod
    def derive_key_with_new_salt(password: str) -> tuple:
        """
        Sinh AES key + salt mới
        
        Args:
            password (str): Mật khẩu của user
        
        Returns:
            tuple: (key, salt)
                - key: AES key (32 bytes)
                - salt: Salt ngẫu nhiên (16 bytes)
        
        Chi tiết:
            - Hàm tiện lợi: sinh salt + derive key cùng lúc
            - Dùng khi user đăng ký (tạo salt mới)
        
        Ví dụ:
            password = "MyPassword"
            key, salt = derive_key_with_new_salt(password)
            → Lưu salt vào database (dùng lại lần sau)
        """
        salt = KeyDerivation.generate_salt()
        key = KeyDerivation.derive_key(password, salt)
        return key, salt


def derive_key_from_password(password: str, salt: bytes = None) -> bytes:
    """
    Hàm tiện lợi: Sinh AES key từ password
    
    Args:
        password (str): Mật khẩu
        salt (bytes, optional): Salt. Nếu None, sinh ngẫu nhiên
    
    Returns:
        bytes: AES key (32 bytes)
    
    Dùng trong test hoặc đơn giản hóa code
    """
    if salt is None:
        salt = KeyDerivation.generate_salt()
    return KeyDerivation.derive_key(password, salt)


def test_key_derivation():
    """
    Test key derivation
    
    ✅ Chạy hàm này để kiểm tra PBKDF2 hoạt động đúng
    """
    print("[✅ TEST KEY DERIVATION]")
    
    # Test 1: Sinh key lần 1
    password = "MySecurePassword123"
    key1, salt1 = KeyDerivation.derive_key_with_new_salt(password)
    
    print(f"Password: {password}")
    print(f"Salt 1 (hex): {salt1.hex()}")
    print(f"Key 1 (hex): {key1.hex()}")
    print(f"Key length: {len(key1)} bytes")
    print()
    
    # Test 2: Cùng password, khác salt → khác key
    key2, salt2 = KeyDerivation.derive_key_with_new_salt(password)
    print(f"Salt 2 (hex): {salt2.hex()}")
    print(f"Key 2 (hex): {key2.hex()}")
    print(f"Khác key: {key1 != key2}")
    print()
    
    # Test 3: Cùng password + salt → cùng key
    key3 = KeyDerivation.derive_key(password, salt1)
    print(f"Derive lại với salt 1:")
    print(f"Key 3 (hex): {key3.hex()}")
    print(f"Giống key 1: {key3 == key1}")
    print()
    
    # Test 4: Khác password → khác key
    password_wrong = "WrongPassword"
    key_wrong, _ = KeyDerivation.derive_key_with_new_salt(password_wrong)
    print(f"Khác password: {password_wrong}")
    print(f"Key (hex): {key_wrong.hex()}")
    print(f"Khác key 1: {key_wrong != key1}")


if __name__ == "__main__":
    test_key_derivation()
