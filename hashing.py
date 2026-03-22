"""
======================================
MODULE: hashing.py
Xử lý hash password với salt
======================================

Chức năng:
- Hash password bằng SHA-256 + salt
- Verify password
- Sinh salt ngẫu nhiên

Tại sao dùng salt?
- Ngăn chặn rainbow table attack
- Hai user cùng password sẽ có hash khác nhau
- Làm tăng độ khó tấn công brute force

Quy trình:
1. Sinh salt ngẫu nhiên (16 bytes)
2. Kết hợp password + salt
3. Hash bằng SHA-256
4. Lưu salt + hash vào database
5. Verify: hash(password_input + salt_lưu) == hash_lưu
"""

import hashlib
import os
from typing import Tuple


class PasswordHasher:
    """Lớp xử lý hash password"""
    
    SALT_LENGTH = 16  # Độ dài salt (bytes)
    HASH_ALGORITHM = 'sha256'  # thuật toán hash
    
    @staticmethod
    def generate_salt() -> bytes:
        """
        Sinh salt ngẫu nhiên
        
        Returns:
            bytes: Salt ngẫu nhiên (16 bytes)
        
        Chi tiết:
            - os.urandom() sinh bytes ngẫu nhiên mạnh (cryptographically secure)
            - 16 bytes = 128 bits, đủ an toàn
        """
        return os.urandom(PasswordHasher.SALT_LENGTH)
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Hash password với salt
        
        Args:
            password (str): Mật khẩu cần hash
            salt (bytes, optional): Salt. Nếu None, sinh ngẫu nhiên
        
        Returns:
            Tuple[bytes, bytes]: (salt, password_hash)
        
        Chi tiết:
            - Nếu không cung cấp salt, sẽ sinh ngẫu nhiên
            - Kết hợp password + salt rồi hash
            - SHA-256 → 32 bytes output
            
        Quy trình:
            password = "123456"
            salt = os.urandom(16)
            combined = password.encode('utf-8') + salt
            hash = SHA-256(combined)
            lưu (salt, hash)
        """
        # Sinh salt nếu chưa có
        if salt is None:
            salt = PasswordHasher.generate_salt()
        
        # Chuyển password → bytes
        password_bytes = password.encode('utf-8')
        
        # Kết hợp password + salt
        combined = password_bytes + salt
        
        # Hash bằng SHA-256
        password_hash = hashlib.sha256(combined).digest()
        
        return salt, password_hash
    
    @staticmethod
    def verify_password(password: str, stored_salt: bytes, stored_hash: bytes) -> bool:
        """
        Verify password (kiểm tra password có khớp không)
        
        Args:
            password (str): Password người dùng nhập
            stored_salt (bytes): Salt được lưu trong DB
            stored_hash (bytes): Hash được lưu trong DB
        
        Returns:
            bool: True nếu password đúng, False nếu sai
        
        Chi tiết:
            - Hash lại password với stored_salt
            - So sánh với stored_hash
        
        Ví dụ:
            user_input = "123456"
            salt, hash = DB lookup
            if verify(user_input, salt, hash):
                → login success
        """
        # Hash password input với stored_salt
        _, computed_hash = PasswordHasher.hash_password(password, stored_salt)
        
        # So sánh (dùng == là ok, hoặc dùng hmac.compare_digest() cho timing attack)
        # Ở đây dùng == đơn giản
        return computed_hash == stored_hash
    
    @staticmethod
    def hash_for_file_integrity(file_content: bytes) -> str:
        """
        Hash file content để check integrity
        
        Args:
            file_content (bytes): Nội dung file
        
        Returns:
            str: Hex string của hash
        
        Chi tiết:
            - Không dùng salt vì không cần bảo mật, chỉ kiểm tra integrity
            - Nếu file bị thay đổi, hash sẽ khác
        
        Ví dụ:
            # Khi lưu file
            hash1 = hash_for_file_integrity(file_content)
            
            # Khi lấy file
            hash2 = hash_for_file_integrity(decrypted_content)
            
            if hash1 != hash2:
                print("File bị thay đổi hoặc giải mã sai!")
        """
        return hashlib.sha256(file_content).hexdigest()


def test_hashing():
    """
    Test hashing/verify
    
    ✅ Chạy hàm này để kiểm tra hashing hoạt động đúng
    """
    print("[✅ TEST HASHING]")
    
    # Test 1: Hash password
    password = "MySecurePassword123"
    salt, hash_value = PasswordHasher.hash_password(password)
    
    print(f"Password: {password}")
    print(f"Salt (hex): {salt.hex()}")
    print(f"Hash (hex): {hash_value.hex()}")
    print()
    
    # Test 2: Verify password đúng
    is_correct = PasswordHasher.verify_password(password, salt, hash_value)
    print(f"Verify correct password: {is_correct}")
    
    # Test 3: Verify password sai
    is_wrong = PasswordHasher.verify_password("WrongPassword", salt, hash_value)
    print(f"Verify wrong password: {is_wrong}")
    print()
    
    # Test 4: Cùng password nhưng khác salt → khác hash
    salt2, hash2 = PasswordHasher.hash_password(password)
    print(f"Cùng password, khác salt:")
    print(f"  Hash 1: {hash_value.hex()}")
    print(f"  Hash 2: {hash2.hex()}")
    print(f"  Khác nhau: {hash_value != hash2}")
    print()
    
    # Test 5: Hash file integrity
    file_content = b"Hello, World!"
    file_hash = PasswordHasher.hash_for_file_integrity(file_content)
    print(f"File hash: {file_hash}")
    
    # Nếu file bị thay đổi
    modified_content = b"Hello, World!!"  # Thêm !
    modified_hash = PasswordHasher.hash_for_file_integrity(modified_content)
    print(f"Modified hash: {modified_hash}")
    print(f"File bị thay đổi: {file_hash != modified_hash}")


if __name__ == "__main__":
    test_hashing()
