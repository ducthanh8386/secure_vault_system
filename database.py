"""
======================================
MODULE: database.py
Quản lý SQLite database
======================================

Chức năng:
- Tạo bảng (tables): users, passwords, files
- CRUD operations (Create, Read, Update, Delete)
- Connection/commit/rollback

Thiết kế bảng:

1. users (lưu account info):
   - id (primary key)
   - username (unique)
   - password_hash (SHA-256)
   - password_salt (random)
   - key_derivation_salt (dùng sinh AES key)
   - created_at

2. passwords (lưu password được mã hóa):
   - id (primary key)
   - user_id (foreign key)
   - site (tên website: gmail, github, ...)
   - username (username trên site)
   - encrypted_password (AES mã hóa)
   - encrypted_password_iv (IV của AES)
   - created_at

3. files (lưu file được mã hóa):
   - id (primary key)
   - user_id (foreign key)
   - file_name (tên file gốc)
   - file_path (đường dẫn file encrypted)
   - file_hash_original (SHA-256 file gốc)
   - file_hash_encrypted (SHA-256 file encrypted)
   - file_size_original
   - created_at
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple


class Database:
    """Lớp quản lý SQLite database"""
    
    def __init__(self, db_path: str = "vault.db"):
        """
        Khởi tạo database
        
        Args:
            db_path (str): Đường dẫn file .db
        """
        self.db_path = db_path
        self.connection = None
        self.cursor = None
    
    def connect(self):
        """Mở kết nối Database"""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row  # Cho phép truy cập theo column name
        self.cursor = self.connection.cursor()
    
    def disconnect(self):
        """Đóng kết nối Database"""
        if self.connection:
            self.connection.close()
    
    def commit(self):
        """Lưu thay đổi vào DB"""
        if self.connection:
            self.connection.commit()
    
    def rollback(self):
        """Hủy thay đổi (nếu có lỗi)"""
        if self.connection:
            self.connection.rollback()
    
    def create_tables(self):
        """
        Tạo tất cả bảng
        
        Chạy hàm này lần đầu tiên để khởi tạo DB
        """
        try:
            # Bảng users
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    password_salt BLOB NOT NULL,
                    key_derivation_salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Bảng passwords
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    site TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    encrypted_password_iv BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            # Bảng files
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_hash_original TEXT NOT NULL,
                    file_hash_encrypted TEXT NOT NULL,
                    file_size_original INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            
            self.commit()
            print("[✅] Database tables created successfully")
        except Exception as e:
            print(f"[❌] Error creating tables: {e}")
            self.rollback()
    
    # ============= USERS TABLE =============
    
    def add_user(self, username: str, password_hash: bytes, password_salt: bytes, 
                 key_derivation_salt: bytes) -> int:
        """
        Thêm user mới
        
        Args:
            username (str): Tên user
            password_hash (bytes): SHA-256 hash (từ hashing.py)
            password_salt (bytes): Salt của password
            key_derivation_salt (bytes): Salt cho PBKDF2
        
        Returns:
            int: User ID (vừa thêm)
        """
        try:
            self.cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, key_derivation_salt)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, password_salt, key_derivation_salt))
            self.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            print(f"[❌] Username '{username}' already exists")
            return -1
        except Exception as e:
            print(f"[❌] Error adding user: {e}")
            return -1
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """
        Lấy thông tin user theo username
        
        Args:
            username (str): Tên user
        
        Returns:
            Dict: {id, username, password_hash, password_salt, key_derivation_salt, created_at}
            None: Nếu user không tồn tại
        """
        try:
            self.cursor.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            )
            row = self.cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            print(f"[❌] Error getting user: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """
        Lấy thông tin user theo ID
        
        Args:
            user_id (int): ID của user
        
        Returns:
            Dict: User info
            None: Nếu không tồn tại
        """
        try:
            self.cursor.execute(
                'SELECT * FROM users WHERE id = ?',
                (user_id,)
            )
            row = self.cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            print(f"[❌] Error getting user by ID: {e}")
            return None
    
    # ============= PASSWORDS TABLE =============
    
    def add_password(self, user_id: int, site: str, username: str, 
                     encrypted_password: bytes, iv: bytes) -> int:
        """
        Thêm password được mã hóa
        
        Args:
            user_id (int): ID của user
            site (str): Website (gmail, github, ...)
            username (str): Username trên site
            encrypted_password (bytes): Password đã mã hóa (AES)
            iv (bytes): IV của AES
        
        Returns:
            int: Password ID
        """
        try:
            self.cursor.execute('''
                INSERT INTO passwords (user_id, site, username, encrypted_password, encrypted_password_iv)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, site, username, encrypted_password, iv))
            self.commit()
            return self.cursor.lastrowid
        except Exception as e:
            print(f"[❌] Error adding password: {e}")
            return -1
    
    def get_passwords_by_user(self, user_id: int) -> List[Dict]:
        """
        Lấy tất cả password của user
        
        Args:
            user_id (int): ID của user
        
        Returns:
            List[Dict]: Danh sách password (encrypted)
        """
        try:
            self.cursor.execute(
                'SELECT * FROM passwords WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            )
            rows = self.cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"[❌] Error getting passwords: {e}")
            return []
    
    def delete_password(self, password_id: int, user_id: int) -> bool:
        """
        Xóa password (chỉ user sở hữu mới được xóa)
        
        Args:
            password_id (int): ID password
            user_id (int): ID user (check ownership)
        
        Returns:
            bool: True nếu thành công
        """
        try:
            self.cursor.execute(
                'DELETE FROM passwords WHERE id = ? AND user_id = ?',
                (password_id, user_id)
            )
            self.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            print(f"[❌] Error deleting password: {e}")
            return False
    
    # ============= FILES TABLE =============
    
    def add_file(self, user_id: int, file_name: str, file_path: str,
                 file_hash_original: str, file_hash_encrypted: str, 
                 file_size_original: int) -> int:
        """
        Thêm file được mã hóa
        
        Args:
            user_id (int): ID user
            file_name (str): Tên file gốc
            file_path (str): Đường dẫn file encrypted
            file_hash_original (str): SHA-256 file gốc
            file_hash_encrypted (str): SHA-256 file encrypted
            file_size_original (int): Kích thước file gốc
        
        Returns:
            int: File ID
        """
        try:
            self.cursor.execute('''
                INSERT INTO files (user_id, file_name, file_path, file_hash_original, 
                                  file_hash_encrypted, file_size_original)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, file_name, file_path, file_hash_original, 
                  file_hash_encrypted, file_size_original))
            self.commit()
            return self.cursor.lastrowid
        except Exception as e:
            print(f"[❌] Error adding file: {e}")
            return -1
    
    def get_files_by_user(self, user_id: int) -> List[Dict]:
        """
        Lấy tất cả file của user
        
        Args:
            user_id (int): ID user
        
        Returns:
            List[Dict]: Danh sách file
        """
        try:
            self.cursor.execute(
                'SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            )
            rows = self.cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"[❌] Error getting files: {e}")
            return []
    
    def delete_file(self, file_id: int, user_id: int) -> bool:
        """
        Xóa file (chỉ user sở hữu mới được xóa)
        
        Args:
            file_id (int): ID file
            user_id (int): ID user (check ownership)
        
        Returns:
            bool: True nếu thành công
        """
        try:
            self.cursor.execute(
                'SELECT file_path FROM files WHERE id = ? AND user_id = ?',
                (file_id, user_id)
            )
            row = self.cursor.fetchone()
            
            if row:
                file_path = row['file_path']
                # Xóa file vật lý
                if os.path.exists(file_path):
                    os.remove(file_path)
                
                # Xóa record trong DB
                self.cursor.execute(
                    'DELETE FROM files WHERE id = ? AND user_id = ?',
                    (file_id, user_id)
                )
                self.commit()
                return True
            return False
        except Exception as e:
            print(f"[❌] Error deleting file: {e}")
            return False
    
    def get_file_by_id(self, file_id: int, user_id: int) -> Optional[Dict]:
        """
        Lấy thông tin file
        
        Args:
            file_id (int): ID file
            user_id (int): ID user
        
        Returns:
            Dict: Thông tin file
            None: Nếu không tồn tại
        """
        try:
            self.cursor.execute(
                'SELECT * FROM files WHERE id = ? AND user_id = ?',
                (file_id, user_id)
            )
            row = self.cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            print(f"[❌] Error getting file: {e}")
            return None


def test_database():
    """
    Test database operations
    
    ✅ Chạy hàm này để kiểm tra DB hoạt động
    """
    import os
    
    # Xóa DB cũ (nếu có)
    test_db = "test_vault.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    print("[✅ TEST DATABASE]")
    
    # Khởi tạo DB
    db = Database(test_db)
    db.connect()
    db.create_tables()
    
    # Test thêm user
    print("\n1. Adding user...")
    uid = db.add_user(
        username="alice",
        password_hash=b"hash_example" * 3,  # Fake hash
        password_salt=b"salt_example" * 2,
        key_derivation_salt=b"kd_salt_example" * 1
    )
    print(f"   User ID: {uid}")
    
    # Test lấy user
    print("\n2. Getting user...")
    user = db.get_user_by_username("alice")
    print(f"   Username: {user['username']}")
    print(f"   Created: {user['created_at']}")
    
    # Test thêm password
    print("\n3. Adding encrypted password...")
    pwd_id = db.add_password(
        user_id=uid,
        site="gmail",
        username="alice@gmail.com",
        encrypted_password=b"encrypted_pwd_data",
        iv=b"random_iv_16bytes"
    )
    print(f"   Password ID: {pwd_id}")
    
    # Test lấy password
    print("\n4. Getting passwords...")
    passwords = db.get_passwords_by_user(uid)
    for pwd in passwords:
        print(f"   - {pwd['site']}: {pwd['username']}")
    
    # Test thêm file
    print("\n5. Adding encrypted file...")
    file_id = db.add_file(
        user_id=uid,
        file_name="secret.txt",
        file_path="./encrypted_files/secret_encrypted.bin",
        file_hash_original="abc123...",
        file_hash_encrypted="def456...",
        file_size_original=1024
    )
    print(f"   File ID: {file_id}")
    
    # Test lấy file
    print("\n6. Getting files...")
    files = db.get_files_by_user(uid)
    for f in files:
        print(f"   - {f['file_name']} ({f['file_size_original']} bytes)")
    
    db.disconnect()
    os.remove(test_db)
    print("\n[✅] Database test passed!")


if __name__ == "__main__":
    test_database()
