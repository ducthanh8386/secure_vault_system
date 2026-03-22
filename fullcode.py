"""
======================================
SECURE VAULT SYSTEM - SINGLE FILE VERSION
Hệ thống lưu trữ mật khẩu & tài liệu an toàn
======================================
"""

import sqlite3
import os
import shutil
import hashlib
import tempfile
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import customtkinter as ctk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ==========================================
# 1. DATABASE MANAGEMENT
# ==========================================
class Database:
    """Lớp quản lý SQLite database"""
    
    def __init__(self, db_path: str = "vault.db"):
        self.db_path = db_path
        self.connection = None
        self.cursor = None
    
    def connect(self):
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
    
    def disconnect(self):
        if self.connection:
            self.connection.close()
    
    def commit(self):
        if self.connection:
            self.connection.commit()
    
    def rollback(self):
        if self.connection:
            self.connection.rollback()
    
    def create_tables(self):
        try:
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
        except Exception as e:
            print(f"[❌] Error creating tables: {e}")
            self.rollback()
    
    def add_user(self, username: str, password_hash: bytes, password_salt: bytes, key_derivation_salt: bytes) -> int:
        try:
            self.cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, key_derivation_salt)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, password_salt, key_derivation_salt))
            self.commit()
            return self.cursor.lastrowid
        except Exception:
            return -1
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        try:
            self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception:
            return None
    
    def add_password(self, user_id: int, site: str, username: str, encrypted_password: bytes, iv: bytes) -> int:
        try:
            self.cursor.execute('''
                INSERT INTO passwords (user_id, site, username, encrypted_password, encrypted_password_iv)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, site, username, encrypted_password, iv))
            self.commit()
            return self.cursor.lastrowid
        except Exception:
            return -1
    
    def get_passwords_by_user(self, user_id: int) -> List[Dict]:
        try:
            self.cursor.execute('SELECT * FROM passwords WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception:
            return []
    
    def delete_password(self, password_id: int, user_id: int) -> bool:
        try:
            self.cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, user_id))
            self.commit()
            return self.cursor.rowcount > 0
        except Exception:
            return False
            
    def add_file(self, user_id: int, file_name: str, file_path: str, file_hash_original: str, file_hash_encrypted: str, file_size_original: int) -> int:
        try:
            self.cursor.execute('''
                INSERT INTO files (user_id, file_name, file_path, file_hash_original, file_hash_encrypted, file_size_original)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, file_name, file_path, file_hash_original, file_hash_encrypted, file_size_original))
            self.commit()
            return self.cursor.lastrowid
        except Exception:
            return -1
            
    def get_files_by_user(self, user_id: int) -> List[Dict]:
        try:
            self.cursor.execute('SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception:
            return []
            
    def delete_file(self, file_id: int, user_id: int) -> bool:
        try:
            self.cursor.execute('SELECT file_path FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
            row = self.cursor.fetchone()
            if row:
                if os.path.exists(row['file_path']):
                    os.remove(row['file_path'])
                self.cursor.execute('DELETE FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
                self.commit()
                return True
            return False
        except Exception:
            return False
            
    def get_file_by_id(self, file_id: int, user_id: int) -> Optional[Dict]:
        try:
            self.cursor.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, user_id))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception:
            return None


# ==========================================
# 2. CRYPTOGRAPHY CORE
# ==========================================
class PasswordHasher:
    SALT_LENGTH = 16
    
    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(PasswordHasher.SALT_LENGTH)
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = PasswordHasher.generate_salt()
        combined = password.encode('utf-8') + salt
        password_hash = hashlib.sha256(combined).digest()
        return salt, password_hash
    
    @staticmethod
    def verify_password(password: str, stored_salt: bytes, stored_hash: bytes) -> bool:
        _, computed_hash = PasswordHasher.hash_password(password, stored_salt)
        return computed_hash == stored_hash
    
    @staticmethod
    def hash_for_file_integrity(file_content: bytes) -> str:
        return hashlib.sha256(file_content).hexdigest()

class AESEncryption:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"Key phải có 32 bytes, nhận {len(key)} bytes")
        self.key = key
        self.backend = default_backend()
    
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        iv = os.urandom(16)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext
    
    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext

class KeyDerivation:
    ITERATIONS = 100000
    SALT_LENGTH = 16
    OUTPUT_LENGTH = 32
    
    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(KeyDerivation.SALT_LENGTH)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KeyDerivation.OUTPUT_LENGTH,
            salt=salt,
            iterations=KeyDerivation.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def derive_key_with_new_salt(password: str) -> tuple:
        salt = KeyDerivation.generate_salt()
        key = KeyDerivation.derive_key(password, salt)
        return key, salt


# ==========================================
# 3. MANAGERS (AUTH, PASSWORD, FILE)
# ==========================================
class AuthManager:
    def __init__(self, db: Database):
        self.db = db
        self.current_user_id = None
        self.current_username = None
        self.current_aes_key = None
    
    def register(self, username: str, password: str) -> bool:
        if not username or len(username) < 3 or not password or len(password) < 6:
            return False
        if self.db.get_user_by_username(username):
            return False
        
        password_salt, password_hash = PasswordHasher.hash_password(password)
        key_derivation_salt = KeyDerivation.generate_salt()
        user_id = self.db.add_user(username, password_hash, password_salt, key_derivation_salt)
        return user_id > 0
    
    def login(self, username: str, password: str) -> bool:
        user = self.db.get_user_by_username(username)
        if not user:
            return False
        if not PasswordHasher.verify_password(password, user['password_salt'], user['password_hash']):
            return False
            
        self.current_user_id = user['id']
        self.current_username = user['username']
        self.current_aes_key = KeyDerivation.derive_key(password, user['key_derivation_salt'])
        return True
    
    def logout(self):
        self.current_user_id = None
        self.current_username = None
        self.current_aes_key = None
    
    def get_session_info(self) -> Dict:
        if not self.current_user_id:
            return None
        return {'user_id': self.current_user_id, 'username': self.current_username, 'aes_key': self.current_aes_key}

class PasswordManager:
    def __init__(self, db: Database, user_id: int, aes_key: bytes):
        self.db = db
        self.user_id = user_id
        self.cipher = AESEncryption(aes_key)
    
    def add_password(self, site: str, username: str, password: str) -> bool:
        if not site or not username or not password:
            return False
        password_bytes = password.encode('utf-8')
        iv, encrypted_password = self.cipher.encrypt(password_bytes)
        pwd_id = self.db.add_password(self.user_id, site, username, encrypted_password, iv)
        return pwd_id > 0
    
    def get_passwords(self) -> List[Dict]:
        return self.db.get_passwords_by_user(self.user_id)
    
    def view_password(self, password_id: int) -> Optional[str]:
        passwords = self.get_passwords()
        for pwd in passwords:
            if pwd['id'] == password_id:
                try:
                    plaintext_bytes = self.cipher.decrypt(pwd['encrypted_password_iv'], pwd['encrypted_password'])
                    return plaintext_bytes.decode('utf-8')
                except Exception:
                    return None
        return None
    
    def delete_password(self, password_id: int) -> bool:
        return self.db.delete_password(password_id, self.user_id)

class FileHandler:
    def __init__(self, db: Database, user_id: int, aes_key: bytes, encrypted_folder: str = "./encrypted_files"):
        self.db = db
        self.user_id = user_id
        self.cipher = AESEncryption(aes_key)
        self.encrypted_folder = encrypted_folder
        Path(self.encrypted_folder).mkdir(parents=True, exist_ok=True)
    
    def upload_file(self, file_path: str) -> bool:
        if not os.path.exists(file_path): return False
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            file_hash_original = PasswordHasher.hash_for_file_integrity(file_content)
            iv, encrypted_content = self.cipher.encrypt(file_content)
            file_hash_encrypted = PasswordHasher.hash_for_file_integrity(encrypted_content)
            
            encrypted_file_path = os.path.join(self.encrypted_folder, f"user_{self.user_id}_{file_name}.encrypted")
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv)
                f.write(encrypted_content)
                
            file_id = self.db.add_file(self.user_id, file_name, encrypted_file_path, file_hash_original, file_hash_encrypted, len(file_content))
            return file_id > 0
        except Exception:
            return False
    
    def download_file(self, file_id: int, save_path: str) -> bool:
        file_info = self.db.get_file_by_id(file_id, self.user_id)
        if not file_info: return False
        try:
            with open(file_info['file_path'], 'rb') as f:
                file_data = f.read()
            iv = file_data[:16]
            encrypted_content = file_data[16:]
            
            if PasswordHasher.hash_for_file_integrity(encrypted_content) != file_info['file_hash_encrypted']:
                return False
                
            decrypted_content = self.cipher.decrypt(iv, encrypted_content)
            if PasswordHasher.hash_for_file_integrity(decrypted_content) != file_info['file_hash_original']:
                return False
                
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)
            return True
        except Exception:
            return False
            
    def delete_file(self, file_id: int) -> bool:
        return self.db.delete_file(file_id, self.user_id)
        
    def list_files(self) -> List[Dict]:
        return self.db.get_files_by_user(self.user_id)


# ==========================================
# 4. GUI IMPLEMENTATION
# ==========================================
COLOR_BG = "#0d1117"
COLOR_FG = "#c9d1d9"
COLOR_ACCENT = "#1f6feb"
COLOR_ACCENT_HOVER = "#388bfd"
COLOR_SUCCESS = "#238636"
COLOR_ERROR = "#da3633"
COLOR_WARNING = "#bf8700"

class SecureVaultGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Vault System")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root.configure(fg_color=COLOR_BG)
        
        self.db = Database("vault.db")
        self.db.connect()
        self.db.create_tables()
        
        self.auth = AuthManager(self.db)
        self.password_manager = None
        self.file_handler = None
        
        self.current_frame = None
        self.show_login_screen()
    
    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
    
    def show_login_screen(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        container = ctk.CTkFrame(self.current_frame, fg_color=COLOR_BG)
        container.pack(expand=True)
        
        title = ctk.CTkLabel(container, text="🔐 SECURE VAULT", font=("Helvetica", 48, "bold"), text_color=COLOR_ACCENT)
        title.pack(pady=20)
        subtitle = ctk.CTkLabel(container, text="Hệ thống lưu trữ mật khẩu & tài liệu an toàn", font=("Helvetica", 14), text_color=COLOR_FG)
        subtitle.pack(pady=(0, 40))
        
        btn_frame = ctk.CTkFrame(container, fg_color=COLOR_BG)
        btn_frame.pack(pady=20)
        
        btn_login = ctk.CTkButton(btn_frame, text="Đăng Nhập", width=200, height=60, font=("Helvetica", 14, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.show_login_form)
        btn_login.grid(row=0, column=0, padx=10)
        btn_register = ctk.CTkButton(btn_frame, text="Đăng Ký", width=200, height=60, font=("Helvetica", 14, "bold"), fg_color=COLOR_SUCCESS, hover_color="#2ea043", command=self.show_register_form)
        btn_register.grid(row=0, column=1, padx=10)
        
        info_frame = ctk.CTkFrame(container, fg_color="#161b22", corner_radius=10)
        info_frame.pack(pady=(40, 0), padx=20, fill="x")
        info_text = "✅ AES-256 Encryption - Mã hóa dữ liệu\n✅ SHA-256 + Salt - Bảo vệ password\n✅ PBKDF2 - Sinh khóa an toàn\n✅ Integrity Check - Kiểm tra file"
        ctk.CTkLabel(info_frame, text=info_text.strip(), font=("Helvetica", 12), text_color=COLOR_FG, justify="left").pack(padx=20, pady=20)
    
    def show_login_form(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        container = ctk.CTkFrame(self.current_frame, fg_color="#161b22", corner_radius=15)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(container, text="ĐĂNG NHẬP", font=("Helvetica", 24, "bold"), text_color=COLOR_ACCENT).pack(pady=20)
        
        ctk.CTkLabel(container, text="Username:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        username_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập username...", corner_radius=8)
        username_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Password:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        password_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập password...", show="*", corner_radius=8)
        password_entry.pack(padx=20, pady=(0, 30))
        
        def login_action():
            username = username_entry.get()
            password = password_entry.get()
            if not username or not password:
                messagebox.showerror("Lỗi", "Vui lòng nhập username và password")
                return
            if self.auth.login(username, password):
                session = self.auth.get_session_info()
                self.password_manager = PasswordManager(self.db, session['user_id'], session['aes_key'])
                self.file_handler = FileHandler(self.db, session['user_id'], session['aes_key'])
                messagebox.showinfo("Thành công", f"Chào mừng {username}!")
                self.show_dashboard()
            else:
                messagebox.showerror("Lỗi", "Username hoặc password sai")
        
        ctk.CTkButton(container, text="Đăng Nhập", width=300, height=45, font=("Helvetica", 14, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=login_action).pack(padx=20, pady=(0, 15))
        ctk.CTkButton(container, text="Quay Lại", width=300, height=40, font=("Helvetica", 12), fg_color="#333", hover_color="#444", command=self.show_login_screen).pack(padx=20, pady=(0, 20))
    
    def show_register_form(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        container = ctk.CTkFrame(self.current_frame, fg_color="#161b22", corner_radius=15)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(container, text="ĐĂNG KÝ", font=("Helvetica", 24, "bold"), text_color=COLOR_ACCENT).pack(pady=20)
        
        ctk.CTkLabel(container, text="Username:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        username_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập username (>= 3 ký tự)...", corner_radius=8)
        username_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Password:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        password_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập password (>= 6 ký tự)...", show="*", corner_radius=8)
        password_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Xác nhận Password:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        confirm_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Xác nhận password...", show="*", corner_radius=8)
        confirm_entry.pack(padx=20, pady=(0, 30))
        
        def register_action():
            username = username_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()
            if not username or not password or not confirm:
                messagebox.showerror("Lỗi", "Vui lòng nhập đầy đủ thông tin")
                return
            if password != confirm:
                messagebox.showerror("Lỗi", "Password không khớp")
                return
            if self.auth.register(username, password):
                messagebox.showinfo("Thành công", "Đăng ký thành công! Vui lòng đăng nhập")
                self.show_login_form()
            else:
                messagebox.showerror("Lỗi", "Đăng ký thất bại (có thể username đã tồn tại)")
        
        ctk.CTkButton(container, text="Đăng Ký", width=300, height=45, font=("Helvetica", 14, "bold"), fg_color=COLOR_SUCCESS, hover_color="#2ea043", command=register_action).pack(padx=20, pady=(0, 15))
        ctk.CTkButton(container, text="Quay Lại", width=300, height=40, font=("Helvetica", 12), fg_color="#333", hover_color="#444", command=self.show_login_screen).pack(padx=20, pady=(0, 20))
    
    def show_dashboard(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        top_bar = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        top_bar.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(top_bar, text=f"👋 Chào {self.auth.current_username}!", font=("Helvetica", 16, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(top_bar, text="Đăng Xuất", width=100, height=40, font=("Helvetica", 12, "bold"), fg_color=COLOR_ERROR, hover_color="#b62324", command=self.logout).pack(side="right", padx=20, pady=10)
        
        menu_frame = ctk.CTkFrame(self.current_frame, fg_color=COLOR_BG)
        menu_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(menu_frame, text="🔐 Quản Lý Mật Khẩu", width=200, height=50, font=("Helvetica", 12, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.show_password_manager).pack(side="left", padx=10)
        ctk.CTkButton(menu_frame, text="📁 Quản Lý File", width=200, height=50, font=("Helvetica", 12, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.show_file_manager).pack(side="left", padx=10)
        ctk.CTkButton(menu_frame, text="ℹ️ Thông Tin", width=200, height=50, font=("Helvetica", 12, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.show_info).pack(side="left", padx=10)
        
        content = ctk.CTkFrame(self.current_frame, fg_color=COLOR_BG)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        welcome_box = ctk.CTkFrame(content, fg_color="#161b22", corner_radius=10)
        welcome_box.pack(fill="both", expand=True, padx=10, pady=10)
        welcome_text = "🎉 Chào mừng đến với Secure Vault!\n\nCác tính năng chính:\n• 🔐 Quản lý mật khẩu (AES-256 mã hóa)\n• 📁 Quản lý file an toàn\n• 🛡️ SHA-256 + PBKDF2 bảo vệ\n• ✅ Integrity checking\n\nHãy chọn một chức năng ở trên để bắt đầu!"
        ctk.CTkLabel(welcome_box, text=welcome_text, font=("Helvetica", 14), text_color=COLOR_FG, justify="left").pack(padx=20, pady=20)
    
    def show_password_manager(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="🔐 QUẢN LÝ MẬT KHẨU", font=("Helvetica", 18, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(header, text="← Quay Lại", width=100, height=40, font=("Helvetica", 11), fg_color="#333", hover_color="#444", command=self.show_dashboard).pack(side="right", padx=20, pady=10)
        
        btn_frame = ctk.CTkFrame(self.current_frame, fg_color=COLOR_BG)
        btn_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="➕ Thêm Password", height=40, font=("Helvetica", 11, "bold"), fg_color=COLOR_SUCCESS, hover_color="#2ea043", command=self.show_add_password).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="👀 Xem Tất Cả", height=40, font=("Helvetica", 11, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.show_view_passwords).pack(side="left", padx=5)
        
        content = ctk.CTkFrame(self.current_frame, fg_color="#161b22", corner_radius=10)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(content, text="Chọn một tùy chọn ở trên để bắt đầu", font=("Helvetica", 14), text_color=COLOR_FG).pack(expand=True)
    
    def show_add_password(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        container = ctk.CTkFrame(self.current_frame, fg_color="#161b22", corner_radius=15)
        container.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(container, text="THÊM MẬT KHẨU MỚI", font=("Helvetica", 20, "bold"), text_color=COLOR_ACCENT).pack(pady=20)
        
        ctk.CTkLabel(container, text="Website/Dịch vụ:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        site_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Ví dụ: Gmail, GitHub...", corner_radius=8)
        site_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Username:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        user_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập username...", corner_radius=8)
        user_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Mật khẩu:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        pwd_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập password...", show="*", corner_radius=8)
        pwd_entry.pack(padx=20, pady=(0, 30))
        
        def save_action():
            site, username, password = site_entry.get(), user_entry.get(), pwd_entry.get()
            if not site or not username or not password:
                messagebox.showerror("Lỗi", "Vui lòng nhập đầy đủ thông tin")
                return
            if self.password_manager.add_password(site, username, password):
                messagebox.showinfo("Thành công", "Mật khẩu đã lưu (mã hóa)")
                self.show_password_manager()
            else:
                messagebox.showerror("Lỗi", "Không thể lưu password")
                
        ctk.CTkButton(container, text="Lưu", width=300, height=45, font=("Helvetica", 14, "bold"), fg_color=COLOR_SUCCESS, hover_color="#2ea043", command=save_action).pack(padx=20, pady=(0, 10))
        ctk.CTkButton(container, text="Quay Lại", width=300, height=40, font=("Helvetica", 12), fg_color="#333", hover_color="#444", command=self.show_password_manager).pack(padx=20, pady=(0, 20))
    
    def show_view_passwords(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="📋 TẤT CẢ MẬT KHẨU", font=("Helvetica", 18, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(header, text="← Quay Lại", width=100, height=40, font=("Helvetica", 11), fg_color="#333", hover_color="#444", command=self.show_password_manager).pack(side="right", padx=20, pady=10)
        
        content = ctk.CTkScrollableFrame(self.current_frame, fg_color="#161b22", corner_radius=10)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        passwords = self.password_manager.get_passwords()
        if not passwords:
            ctk.CTkLabel(content, text="Chưa có password nào được lưu", font=("Helvetica", 14), text_color=COLOR_FG).pack(padx=20, pady=20)
        else:
            for pwd in passwords:
                pwd_frame = ctk.CTkFrame(content, fg_color="#0d1117", corner_radius=8)
                pwd_frame.pack(fill="x", padx=10, pady=5)
                ctk.CTkLabel(pwd_frame, text=f"🌐 {pwd['site']}  |  👤 {pwd['username']}", font=("Helvetica", 12), text_color=COLOR_FG).pack(anchor="w", padx=15, pady=(10, 5))
                
                btn_frame = ctk.CTkFrame(pwd_frame, fg_color="#0d1117")
                btn_frame.pack(anchor="w", padx=15, pady=(0, 10))
                
                def view_pwd(pid=pwd['id'], s=pwd['site']):
                    dec = self.password_manager.view_password(pid)
                    if dec: messagebox.showinfo(f"Password - {s}", f"Password: {dec}")
                
                def delete_pwd(pid=pwd['id']):
                    if messagebox.askyesno("Xác nhận", "Bạn chắc chắn muốn xóa?"):
                        self.password_manager.delete_password(pid)
                        self.show_view_passwords()
                
                ctk.CTkButton(btn_frame, text="👀 Xem", width=80, height=30, font=("Helvetica", 10), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=view_pwd).pack(side="left", padx=5)
                ctk.CTkButton(btn_frame, text="🗑️ Xóa", width=80, height=30, font=("Helvetica", 10), fg_color=COLOR_ERROR, hover_color="#b62324", command=delete_pwd).pack(side="left", padx=5)
    
    def show_file_manager(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="📁 QUẢN LÝ FILE", font=("Helvetica", 18, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(header, text="← Quay Lại", width=100, height=40, font=("Helvetica", 11), fg_color="#333", hover_color="#444", command=self.show_dashboard).pack(side="right", padx=20, pady=10)
        
        btn_frame = ctk.CTkFrame(self.current_frame, fg_color=COLOR_BG)
        btn_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="📤 Upload File", height=40, font=("Helvetica", 11, "bold"), fg_color=COLOR_SUCCESS, hover_color="#2ea043", command=self.show_upload_file).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📋 Xem Tất Cả", height=40, font=("Helvetica", 11, "bold"), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.show_view_files).pack(side="left", padx=5)
        
        content = ctk.CTkFrame(self.current_frame, fg_color="#161b22", corner_radius=10)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(content, text="Chọn một tùy chọn ở trên để bắt đầu", font=("Helvetica", 14), text_color=COLOR_FG).pack(expand=True)
    
    def show_upload_file(self):
        file_path = filedialog.askopenfilename(title="Chọn file để upload", filetypes=[("All files", "*.*")])
        if not file_path: return
        if self.file_handler.upload_file(file_path):
            messagebox.showinfo("Thành công", "File upload thành công (mã hóa)")
            self.show_file_manager()
        else:
            messagebox.showerror("Lỗi", "Không thể upload file")
    
    def show_view_files(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="📂 TẤT CẢ FILE", font=("Helvetica", 18, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(header, text="← Quay Lại", width=100, height=40, font=("Helvetica", 11), fg_color="#333", hover_color="#444", command=self.show_file_manager).pack(side="right", padx=20, pady=10)
        
        content = ctk.CTkScrollableFrame(self.current_frame, fg_color="#161b22", corner_radius=10)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        files = self.file_handler.list_files()
        if not files:
            ctk.CTkLabel(content, text="Chưa có file nào được upload", font=("Helvetica", 14), text_color=COLOR_FG).pack(padx=20, pady=20)
        else:
            for f in files:
                file_frame = ctk.CTkFrame(content, fg_color="#0d1117", corner_radius=8)
                file_frame.pack(fill="x", padx=10, pady=5)
                size_kb = f['file_size_original'] / 1024
                ctk.CTkLabel(file_frame, text=f"📄 {f['file_name']}  |  💾 {size_kb:.2f}KB", font=("Helvetica", 12), text_color=COLOR_FG).pack(anchor="w", padx=15, pady=(10, 5))
                
                btn_frame = ctk.CTkFrame(file_frame, fg_color="#0d1117")
                btn_frame.pack(anchor="w", padx=15, pady=(0, 10))
                
                def view_file_securely(fid=f['id'], fname=f['file_name']):
                    temp_dir = tempfile.mkdtemp()
                    temp_path = os.path.join(temp_dir, fname)
                    if self.file_handler.download_file(fid, temp_path):
                        try:
                            if platform.system() == 'Darwin': subprocess.call(('open', temp_path))
                            elif platform.system() == 'Windows': os.startfile(temp_path)
                            else: subprocess.call(('xdg-open', temp_path))
                            messagebox.showinfo("Đang xem file 👁️", f"Đang xem: '{fname}'.\n\n⚠ BẢO MẬT: Nhấn OK sau khi xem xong để xóa file tạm.")
                        except Exception as e:
                            messagebox.showerror("Lỗi", f"Không thể mở ứng dụng: {e}")
                        finally:
                            try:
                                if os.path.exists(temp_path): os.remove(temp_path)
                                if os.path.exists(temp_dir): os.rmdir(temp_dir)
                            except Exception:
                                pass
                    else:
                        messagebox.showerror("Lỗi", "Không thể giải mã file.")

                def download_file(fid=f['id']):
                    save_path = filedialog.asksaveasfilename(defaultextension=f['file_name'], filetypes=[("All files", "*.*")])
                    if not save_path: return
                    if self.file_handler.download_file(fid, save_path):
                        messagebox.showinfo("Thành công", "File download thành công")
                    else:
                        messagebox.showerror("Lỗi", "Không thể download file")
                
                def delete_file(fid=f['id']):
                    if messagebox.askyesno("Xác nhận", "Bạn chắc chắn muốn xóa?"):
                        self.file_handler.delete_file(fid)
                        self.show_view_files()
                
                ctk.CTkButton(btn_frame, text="👀 Xem", width=90, height=30, font=("Helvetica", 10, "bold"), fg_color="#2ea043", hover_color="#238636", command=view_file_securely).pack(side="left", padx=5)
                ctk.CTkButton(btn_frame, text="📥 Download", width=90, height=30, font=("Helvetica", 10), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=download_file).pack(side="left", padx=5)
                ctk.CTkButton(btn_frame, text="🗑️ Xóa", width=80, height=30, font=("Helvetica", 10), fg_color=COLOR_ERROR, hover_color="#b62324", command=delete_file).pack(side="left", padx=5)
    
    def show_info(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="ℹ️ THÔNG TIN", font=("Helvetica", 18, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(header, text="← Quay Lại", width=100, height=40, font=("Helvetica", 11), fg_color="#333", hover_color="#444", command=self.show_dashboard).pack(side="right", padx=20, pady=10)
        
        content = ctk.CTkScrollableFrame(self.current_frame, fg_color="#161b22", corner_radius=10)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        pwds = len(self.password_manager.get_passwords())
        files = len(self.file_handler.list_files())
        info_text = f"👤 THÔNG TIN NGƯỜI DÙNG\nUsername: {self.auth.current_username}\nUser ID: {self.auth.current_user_id}\n\n📊 THỐNG KÊ\nPassword lưu: {pwds}\nFile lưu: {files}\n\n🔐 BẢO MẬT\n✅ Password User: SHA-256 + salt\n✅ AES Key Derivation: PBKDF2 (100,000 iter)\n✅ Password & File: AES-256-CBC mã hóa\n✅ File Integrity: SHA-256 check\n\n🛡️ MỨC ĐỘ BẢO MẬT: EXCELLENT"
        ctk.CTkLabel(content, text=info_text, font=("Helvetica", 12), text_color=COLOR_FG, justify="left").pack(padx=20, pady=20, fill="both", expand=True)
    
    def logout(self):
        self.auth.logout()
        self.password_manager = None
        self.file_handler = None
        self.show_login_screen()
    
    def on_closing(self):
        self.db.disconnect()
        self.root.destroy()

# ==========================================
# 5. MAIN EXECUTION
# ==========================================
def main():
    root = ctk.CTk()
    app = SecureVaultGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()