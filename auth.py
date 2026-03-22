"""
======================================
MODULE: auth.py
Xử lý authentication (đăng ký / đăng nhập)
======================================

Chức năng:
- Đăng ký user mới
- Đăng nhập (verify password)
- Quản lý session

Quy trình đăng ký:
1. Nhập username + password
2. Check username chưa tồn tại
3. Sinh password_salt ngẫu nhiên
4. Hash password: SHA-256(password + salt)
5. Sinh key_derivation_salt (dùng sinh AES key)
6. Lưu vào DB: (username, password_hash, password_salt, key_derivation_salt)

Quy trình đăng nhập:
1. Nhập username + password
2. Lấy user từ DB
3. Hash password_input: SHA-256(password_input + password_salt_từ_DB)
4. So sánh hash
5. Nếu đúng → tạo session (lưu user_id, AES_key)
"""

from hashing import PasswordHasher
from key_derivation import KeyDerivation
from database import Database
from typing import Optional, Dict


class AuthManager:
    """Lớp quản lý authentication"""
    
    def __init__(self, db: Database):
        """
        Khởi tạo AuthManager
        
        Args:
            db (Database): Instance của Database
        """
        self.db = db
        self.current_user_id = None  # Lưu ID user đăng nhập hiện tại
        self.current_username = None
        self.current_aes_key = None  # AES key dùng encrypt dữ liệu
    
    def register(self, username: str, password: str) -> bool:
        """
        Đăng ký user mới
        
        Args:
            username (str): Tên user (phải unique)
            password (str): Mật khẩu (tối thiểu 6 ký tự)
        
        Returns:
            bool: True nếu đăng ký thành công
        
        Chi tiết:
            1. Validate input
            2. Sinh password_salt
            3. Hash password
            4. Sinh key_derivation_salt
            5. Lưu vào DB
        """
        # Validate input
        if not username or len(username) < 3:
            print("[❌] Username phải >= 3 ký tự")
            return False
        
        if not password or len(password) < 6:
            print("[❌] Password phải >= 6 ký tự")
            return False
        
        # Check username đã tồn tại
        existing_user = self.db.get_user_by_username(username)
        if existing_user:
            print(f"[❌] Username '{username}' đã tồn tại")
            return False
        
        # Sinh password_salt + hash password
        password_salt, password_hash = PasswordHasher.hash_password(password)
        
        # Sinh key_derivation_salt (dùng lúc đăng nhập để sinh AES key)
        key_derivation_salt = KeyDerivation.generate_salt()
        
        # Lưu vào DB
        user_id = self.db.add_user(
            username=username,
            password_hash=password_hash,
            password_salt=password_salt,
            key_derivation_salt=key_derivation_salt
        )
        
        if user_id > 0:
            print(f"[✅] Đăng ký thành công! Welcome {username}")
            return True
        else:
            return False
    
    def login(self, username: str, password: str) -> bool:
        """
        Đăng nhập
        
        Args:
            username (str): Tên user
            password (str): Mật khẩu
        
        Returns:
            bool: True nếu đăng nhập thành công
        
        Chi tiết:
            1. Lấy user từ DB
            2. Hash password input
            3. So sánh hash
            4. Nếu đúng → tạo session (lưu user_id + sinh AES key)
        """
        # Lấy user từ DB
        user = self.db.get_user_by_username(username)
        if not user:
            print(f"[❌] User '{username}' không tồn tại")
            return False
        
        # Verify password
        is_correct = PasswordHasher.verify_password(
            password,
            user['password_salt'],
            user['password_hash']
        )
        
        if not is_correct:
            print("[❌] Password sai")
            return False
        
        # Tạo session
        self.current_user_id = user['id']
        self.current_username = user['username']
        
        # Sinh AES key từ password + key_derivation_salt
        self.current_aes_key = KeyDerivation.derive_key(
            password,
            user['key_derivation_salt']
        )
        
        print(f"[✅] Đăng nhập thành công! Welcome {username}")
        return True
    
    def logout(self):
        """
        Đăng xuất
        
        Xóa session hiện tại
        """
        self.current_user_id = None
        self.current_username = None
        self.current_aes_key = None
        print("[✅] Đã đăng xuất")
    
    def is_logged_in(self) -> bool:
        """
        Kiểm tra user đã đăng nhập chưa
        
        Returns:
            bool: True nếu đã đăng nhập
        """
        return self.current_user_id is not None
    
    def get_session_info(self) -> Dict:
        """
        Lấy thông tin session hiện tại
        
        Returns:
            Dict: {user_id, username, aes_key}
            None: Nếu chưa đăng nhập
        """
        if not self.is_logged_in():
            return None
        
        return {
            'user_id': self.current_user_id,
            'username': self.current_username,
            'aes_key': self.current_aes_key
        }


def test_auth():
    """
    Test authentication
    
    ✅ Chạy hàm này để kiểm tra auth hoạt động
    """
    import os
    
    # Xóa DB cũ
    test_db = "test_auth.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    print("[✅ TEST AUTHENTICATION]")
    
    # Khởi tạo
    db = Database(test_db)
    db.connect()
    db.create_tables()
    
    auth = AuthManager(db)
    
    # Test 1: Đăng ký
    print("\n1. Register user...")
    auth.register("alice", "SecurePassword123")
    
    # Test 2: Đăng ký duplicate
    print("\n2. Register duplicate (should fail)...")
    auth.register("alice", "AnotherPassword")
    
    # Test 3: Đăng nhập đúng
    print("\n3. Login with correct password...")
    auth.login("alice", "SecurePassword123")
    print(f"   Logged in: {auth.is_logged_in()}")
    print(f"   AES key (hex): {auth.current_aes_key.hex()[:32]}...")
    
    # Test 4: Kiểm tra session
    print("\n4. Session info...")
    session = auth.get_session_info()
    print(f"   User ID: {session['user_id']}")
    print(f"   Username: {session['username']}")
    
    # Test 5: Đăng xuất
    print("\n5. Logout...")
    auth.logout()
    print(f"   Logged in: {auth.is_logged_in()}")
    
    # Test 6: Đăng nhập sai
    print("\n6. Login with wrong password...")
    auth.login("alice", "WrongPassword")
    
    # Test 7: Đăng nhập lại đúng
    print("\n7. Login again...")
    auth.login("alice", "SecurePassword123")
    print(f"   Logged in: {auth.is_logged_in()}")
    
    db.disconnect()
    os.remove(test_db)
    print("\n[✅] Auth test passed!")


if __name__ == "__main__":
    test_auth()
