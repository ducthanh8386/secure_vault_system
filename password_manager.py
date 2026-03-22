"""
======================================
MODULE: password_manager.py
Quản lý password được mã hóa
======================================

Chức năng:
- Thêm password (mã hóa bằng AES)
- Xem/giải mã password
- Xóa password

Quy trình lưu password:
1. User nhập: site, username, password
2. Mã hóa password bằng AES (dùng user's AES key)
3. Lưu vào DB: (site, username, encrypted_password, IV)
4. File DB bây giờ có dữ liệu: encrypted

Quy trình xem password:
1. Lấy encrypted password + IV từ DB
2. Giải mã bằng AES (dùng user's AES key)
3. Hiển thị plaintext password

⚠️ QUAN TRỌNG:
- Mỗi user có AES key riêng (sinh từ password của user)
- User A không thể mã hóa/giải mã dữ liệu của User B
- Nếu password user bị lộ → tất cả password user đó bị mã hóa nhưng không thể giải mã
"""

from encryption import AESEncryption
from database import Database
from typing import List, Dict, Optional


class PasswordManager:
    """Lớp quản lý password được mã hóa"""
    
    def __init__(self, db: Database, user_id: int, aes_key: bytes):
        """
        Khởi tạo PasswordManager
        
        Args:
            db (Database): Instance Database
            user_id (int): ID user hiện tại
            aes_key (bytes): AES key của user
        """
        self.db = db
        self.user_id = user_id
        self.cipher = AESEncryption(aes_key)
    
    def add_password(self, site: str, username: str, password: str) -> bool:
        """
        Thêm password mới (được mã hóa)
        
        Args:
            site (str): Website (gmail, github, ...)
            username (str): Username trên site
            password (str): Password (sẽ được mã hóa)
        
        Returns:
            bool: True nếu thành công
        
        Chi tiết:
            1. Validate input
            2. Mã hóa password bằng AES
            3. Lưu vào DB (encrypted)
        """
        # Validate
        # Validate
        if not site or not username or not password:
            print("[❌] Site, username, password không được để trống")
            return False
        
        # SỬA Ở ĐÂY: Chuyển password (string) sang bytes trước khi mã hóa
        password_bytes = password.encode('utf-8')
        iv, encrypted_password = self.cipher.encrypt(password_bytes)
        
        # Lưu vào DB
        pwd_id = self.db.add_password(
            user_id=self.user_id,
            site=site,
            username=username,
            encrypted_password=encrypted_password,
            iv=iv
        )
        
        if pwd_id > 0:
            print(f"[✅] Password cho '{site}' đã lưu (mã hóa)")
            return True
        else:
            return False
    
    def get_passwords(self) -> List[Dict]:
        """
        Lấy tất cả password của user (encrypted)
        
        Returns:
            List[Dict]: Danh sách password
        """
        return self.db.get_passwords_by_user(self.user_id)
    
    def view_password(self, password_id: int) -> Optional[str]:
        """
        Xem password (giải mã)
        
        Args:
            password_id (int): ID password
        
        Returns:
            str: Password plaintext
            None: Nếu không tồn tại hoặc lỗi giải mã
        
        Chi tiết:
            1. Lấy encrypted password + IV từ DB
            2. Giải mã bằng AES
            3. Trả về plaintext
        """
        passwords = self.db.get_passwords_by_user(self.user_id)
        
        for pwd in passwords:
            if pwd['id'] == password_id:
                try:
                    # SỬA Ở ĐÂY: Giải mã sẽ trả về bytes, ta cần chuyển lại thành string
                    plaintext_bytes = self.cipher.decrypt(
                        pwd['encrypted_password_iv'],
                        pwd['encrypted_password']
                    )
                    return plaintext_bytes.decode('utf-8')
                except Exception as e:
                    print(f"[❌] Lỗi giải mã: {e}")
                    return None
        
        print(f"[❌] Password ID {password_id} không tồn tại")
        return None
    
    def delete_password(self, password_id: int) -> bool:
        """
        Xóa password
        
        Args:
            password_id (int): ID password
        
        Returns:
            bool: True nếu xóa thành công
        """
        result = self.db.delete_password(password_id, self.user_id)
        if result:
            print(f"[✅] Password ID {password_id} đã xóa")
        else:
            print(f"[❌] Không thể xóa password ID {password_id}")
        return result
    
    def list_all_passwords(self, show_plaintext: bool = False):
        """
        Liệt kê tất cả password
        
        Args:
            show_plaintext (bool): Có hiển thị plaintext password không
        
        Chi tiết:
            - Mặc định chỉ hiển thị site + username
            - Nếu show_plaintext=True, sẽ giải mã + hiển thị password
            - ⚠️ Cẩn thận: passwords sẽ được giải mã (confidentiality risk)
        """
        passwords = self.get_passwords()
        
        if not passwords:
            print("Không có password nào được lưu")
            return
        
        print("\n" + "="*60)
        print(f"{'ID':<5} {'Site':<15} {'Username':<25} {'Password':<15}")
        print("="*60)
        
        for pwd in passwords:
            pwd_display = "***hidden***"
            if show_plaintext:
                decrypted = self.view_password(pwd['id'])
                pwd_display = decrypted if decrypted else "***error***"
            
            print(f"{pwd['id']:<5} {pwd['site']:<15} {pwd['username']:<25} {pwd_display:<15}")
        
        print("="*60 + "\n")


def test_password_manager():
    """
    Test password manager
    
    ✅ Chạy hàm này để kiểm tra password manager hoạt động
    """
    import os
    from key_derivation import KeyDerivation
    
    # Xóa DB cũ
    test_db = "test_pm.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    print("[✅ TEST PASSWORD MANAGER]")
    
    # Setup
    db = Database(test_db)
    db.connect()
    db.create_tables()
    
    # Tạo user
    from hashing import PasswordHasher
    password_salt, password_hash = PasswordHasher.hash_password("MyPassword123")
    key_derivation_salt = KeyDerivation.generate_salt()
    
    user_id = db.add_user(
        username="alice",
        password_hash=password_hash,
        password_salt=password_salt,
        key_derivation_salt=key_derivation_salt
    )
    
    # Sinh AES key
    aes_key = KeyDerivation.derive_key("MyPassword123", key_derivation_salt)
    
    # Tạo PasswordManager
    pm = PasswordManager(db, user_id, aes_key)
    
    # Test 1: Thêm password
    print("\n1. Adding passwords...")
    pm.add_password("gmail", "alice@gmail.com", "GmailPassword123!")
    pm.add_password("github", "alice_dev", "GitHubPassword456@")
    pm.add_password("facebook", "alice_user", "FBPassword789#")
    
    # Test 2: Liệt kê password (encrypted)
    print("\n2. Listing passwords (encrypted)...")
    pm.list_all_passwords(show_plaintext=False)
    
    # Test 3: Xem password (giải mã)
    print("3. Viewing decrypted passwords...")
    passwords = pm.get_passwords()
    print(f"   Gmail password: {pm.view_password(passwords[0]['id'])}")
    print(f"   GitHub password: {pm.view_password(passwords[1]['id'])}")
    
    # Test 4: Liệt kê password (plaintext)
    print("\n4. Listing passwords (plaintext)...")
    pm.list_all_passwords(show_plaintext=True)
    
    # Test 5: Xóa password
    print("\n5. Deleting password...")
    pm.delete_password(passwords[0]['id'])
    print("\n   After deletion:")
    pm.list_all_passwords()
    
    db.disconnect()
    os.remove(test_db)
    print("\n[✅] Password Manager test passed!")


if __name__ == "__main__":
    test_password_manager()
