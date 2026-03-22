"""
======================================
MODULE: main.py (CLI Interface)
Giao diện dòng lệnh cho Secure Vault System
======================================

Menu chính:
1. Register / Login
2. Password Manager
3. File Manager
4. System Info
5. Logout
6. Exit

Lưu ý:
- Must login before accessing password/file manager
- Mỗi user có AES key riêng (không thể truy cập dữ liệu user khác)
"""

import os
import sys
from getpass import getpass  # Input password ẩn (không hiển thị trên màn hình)
from database import Database
from auth import AuthManager
from password_manager import PasswordManager
from file_handler import FileHandler


class SecureVaultApp:
    """Ứng dụng Secure Vault System"""
    
    def __init__(self, db_path: str = "vault.db"):
        """
        Khởi tạo ứng dụng
        
        Args:
            db_path (str): Đường dẫn database
        """
        self.db = Database(db_path)
        self.db.connect()
        self.db.create_tables()
        
        self.auth = AuthManager(self.db)
        self.password_manager = None
        self.file_handler = None
    
    def clear_screen(self):
        """Xóa màn hình"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """In banner"""
        print("\n")
        print("="*60)
        print("       🔐 SECURE VAULT SYSTEM 🔐")
        print("  Hệ thống lưu trữ mật khẩu & tài liệu an toàn")
        print("="*60)
        print()
    
    def print_main_menu(self):
        """In menu chính"""
        print("\n" + "="*60)
        print("MENU CHÍNH")
        print("="*60)
        
        if self.auth.is_logged_in():
            print(f"Đang đăng nhập: {self.auth.current_username}")
            print()
            print("1. Quản lý mật khẩu")
            print("2. Quản lý file")
            print("3. Thông tin hệ thống")
            print("4. Đăng xuất")
            print("5. Thoát")
        else:
            print("1. Đăng ký")
            print("2. Đăng nhập")
            print("3. Thoát")
        
        print("="*60)
    
    def handle_auth_menu(self):
        """Xử lý menu authentication"""
        while not self.auth.is_logged_in():
            self.clear_screen()
            self.print_banner()
            self.print_main_menu()
            
            choice = input("Chọn: ").strip()
            
            if choice == '1':
                self.handle_register()
            elif choice == '2':
                self.handle_login()
            elif choice == '3':
                print("\n[👋] Tạm biệt!")
                sys.exit(0)
            else:
                print("[❌] Lựa chọn không hợp lệ")
                input("Bấm Enter để tiếp tục...")
    
    def handle_register(self):
        """Xử lý đăng ký"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("ĐĂNG KÝ")
        print("=" * 60)
        
        username = input("Username (>= 3 ký tự): ").strip()
        password = getpass("Password (>= 6 ký tự): ")
        password_confirm = getpass("Xác nhận password: ")
        
        if password != password_confirm:
            print("[❌] Password không khớp!")
            input("Bấm Enter để tiếp tục...")
            return
        
        if self.auth.register(username, password):
            input("Bấm Enter để tiếp tục...")
        else:
            input("Bấm Enter để tiếp tục...")
    
    def handle_login(self):
        """Xử lý đăng nhập"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("ĐĂNG NHẬP")
        print("=" * 60)
        
        username = input("Username: ").strip()
        password = getpass("Password: ")
        
        if self.auth.login(username, password):
            # Tạo password manager + file handler sau khi login
            session = self.auth.get_session_info()
            self.password_manager = PasswordManager(
                self.db,
                session['user_id'],
                session['aes_key']
            )
            self.file_handler = FileHandler(
                self.db,
                session['user_id'],
                session['aes_key']
            )
            input("Bấm Enter để tiếp tục...")
        else:
            input("Bấm Enter để tiếp tục...")
    
    def handle_password_manager_menu(self):
        """Xử lý menu Password Manager"""
        while self.auth.is_logged_in():
            self.clear_screen()
            self.print_banner()
            print("\n" + "="*60)
            print("QUẢN LÝ MẬT KHẨU")
            print("="*60)
            print("1. Thêm mật khẩu")
            print("2. Xem tất cả mật khẩu")
            print("3. Xem mật khẩu chi tiết")
            print("4. Xóa mật khẩu")
            print("5. Quay lại menu chính")
            print("="*60)
            
            choice = input("Chọn: ").strip()
            
            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.view_all_passwords()
            elif choice == '3':
                self.view_password_detail()
            elif choice == '4':
                self.delete_password()
            elif choice == '5':
                break
            else:
                print("[❌] Lựa chọn không hợp lệ")
                input("Bấm Enter để tiếp tục...")
    
    def add_password(self):
        """Thêm mật khẩu mới"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("THÊM MẬT KHẨU MỚI")
        print("=" * 60)
        
        site = input("Website/Tên dịch vụ: ").strip()
        username = input("Username trên dịch vụ: ").strip()
        password = getpass("Mật khẩu: ")
        
        if self.password_manager.add_password(site, username, password):
            input("Bấm Enter để tiếp tục...")
        else:
            input("Bấm Enter để tiếp tục...")
    
    def view_all_passwords(self):
        """Xem tất cả mật khẩu"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("TẤT CẢ MẬT KHẨU (MÃ HÓA)")
        print("=" * 60)
        
        self.password_manager.list_all_passwords(show_plaintext=False)
        input("Bấm Enter để tiếp tục...")
    
    def view_password_detail(self):
        """Xem mật khẩu chi tiết (giải mã)"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("XEM MẬT KHẨU CHI TIẾT")
        print("=" * 60)
        
        passwords = self.password_manager.get_passwords()
        if not passwords:
            print("Không có mật khẩu nào")
            input("Bấm Enter để tiếp tục...")
            return
        
        # Hiển thị danh sách
        print("\nDanh sách mật khẩu:")
        for pwd in passwords:
            print(f"ID {pwd['id']}: {pwd['site']} ({pwd['username']})")
        
        pwd_id = input("\nNhập ID mật khẩu: ").strip()
        try:
            pwd_id = int(pwd_id)
            plaintext = self.password_manager.view_password(pwd_id)
            if plaintext:
                print(f"\n✅ Mật khẩu: {plaintext}")
        except ValueError:
            print("[❌] ID không hợp lệ")
        
        input("\nBấm Enter để tiếp tục...")
    
    def delete_password(self):
        """Xóa mật khẩu"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("XÓA MẬT KHẨU")
        print("=" * 60)
        
        passwords = self.password_manager.get_passwords()
        if not passwords:
            print("Không có mật khẩu nào")
            input("Bấm Enter để tiếp tục...")
            return
        
        print("\nDanh sách mật khẩu:")
        for pwd in passwords:
            print(f"ID {pwd['id']}: {pwd['site']}")
        
        pwd_id = input("\nNhập ID mật khẩu muốn xóa: ").strip()
        try:
            pwd_id = int(pwd_id)
            self.password_manager.delete_password(pwd_id)
        except ValueError:
            print("[❌] ID không hợp lệ")
        
        input("Bấm Enter để tiếp tục...")
    
    def handle_file_manager_menu(self):
        """Xử lý menu File Manager"""
        while self.auth.is_logged_in():
            self.clear_screen()
            self.print_banner()
            print("\n" + "="*60)
            print("QUẢN LÝ FILE")
            print("="*60)
            print("1. Upload file (mã hóa)")
            print("2. Xem tất cả file")
            print("3. Download file (giải mã)")
            print("4. Xóa file")
            print("5. Quay lại menu chính")
            print("="*60)
            
            choice = input("Chọn: ").strip()
            
            if choice == '1':
                self.upload_file()
            elif choice == '2':
                self.view_all_files()
            elif choice == '3':
                self.download_file()
            elif choice == '4':
                self.delete_file()
            elif choice == '5':
                break
            else:
                print("[❌] Lựa chọn không hợp lệ")
                input("Bấm Enter để tiếp tục...")
    
    def upload_file(self):
        """Upload file"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("UPLOAD FILE (MÃ HÓA)")
        print("=" * 60)
        
        file_path = input("Nhập đường dẫn file: ").strip()
        
        if self.file_handler.upload_file(file_path):
            pass
        
        input("Bấm Enter để tiếp tục...")
    
    def view_all_files(self):
        """Xem tất cả file"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("TẤT CẢ FILE")
        print("=" * 60)
        
        self.file_handler.list_files_pretty()
        input("Bấm Enter để tiếp tục...")
    
    def download_file(self):
        """Download file"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("DOWNLOAD FILE (GIẢI MÃ)")
        print("=" * 60)
        
        files = self.file_handler.list_files()
        if not files:
            print("Không có file nào")
            input("Bấm Enter để tiếp tục...")
            return
        
        print("\nDanh sách file:")
        for f in files:
            print(f"ID {f['id']}: {f['file_name']}")
        
        file_id = input("\nNhập ID file: ").strip()
        save_path = input("Nhập đường dẫn lưu file: ").strip()
        
        try:
            file_id = int(file_id)
            self.file_handler.download_file(file_id, save_path)
        except ValueError:
            print("[❌] ID không hợp lệ")
        
        input("Bấm Enter để tiếp tục...")
    
    def delete_file(self):
        """Xóa file"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("XÓA FILE")
        print("=" * 60)
        
        files = self.file_handler.list_files()
        if not files:
            print("Không có file nào")
            input("Bấm Enter để tiếp tục...")
            return
        
        print("\nDanh sách file:")
        for f in files:
            print(f"ID {f['id']}: {f['file_name']}")
        
        file_id = input("\nNhập ID file muốn xóa: ").strip()
        
        try:
            file_id = int(file_id)
            self.file_handler.delete_file(file_id)
        except ValueError:
            print("[❌] ID không hợp lệ")
        
        input("Bấm Enter để tiếp tục...")
    
    def show_system_info(self):
        """Hiển thị thông tin hệ thống"""
        self.clear_screen()
        self.print_banner()
        print("=" * 60)
        print("THÔNG TIN HỆ THỐNG")
        print("=" * 60)
        
        if self.auth.is_logged_in():
            print(f"\n✅ Trạng thái: Đã đăng nhập")
            print(f"Username: {self.auth.current_username}")
            print(f"User ID: {self.auth.current_user_id}")
            print(f"AES Key (hex): {self.auth.current_aes_key.hex()[:32]}...")
            
            passwords = self.password_manager.get_passwords()
            files = self.file_handler.list_files()
            
            print(f"\nPassword lưu: {len(passwords)}")
            print(f"File lưu: {len(files)}")
            
            print("\n🔒 BẢO MẬT:")
            print("- Password user: SHA-256 + salt")
            print("- AES key: PBKDF2 (100k iterations)")
            print("- Password lưu: AES-256 mã hóa")
            print("- File: AES-256 mã hóa + SHA-256 integrity check")
        
        print("\n" + "=" * 60)
        input("Bấm Enter để tiếp tục...")
    
    def run(self):
        """Chạy ứng dụng"""
        self.print_banner()
        
        # Đăng ký / Đăng nhập
        self.handle_auth_menu()
        
        # Menu chính
        while self.auth.is_logged_in():
            self.clear_screen()
            self.print_banner()
            self.print_main_menu()
            
            choice = input("Chọn: ").strip()
            
            if choice == '1':
                self.handle_password_manager_menu()
            elif choice == '2':
                self.handle_file_manager_menu()
            elif choice == '3':
                self.show_system_info()
            elif choice == '4':
                self.auth.logout()
                print("Redirect to login...")
                self.handle_auth_menu()
            elif choice == '5':
                print("\n[👋] Tạm biệt!")
                break
            else:
                print("[❌] Lựa chọn không hợp lệ")
                input("Bấm Enter để tiếp tục...")
        
        # Cleanup
        self.db.disconnect()
        print("\n[✅] Ứng dụng đã thoát")


if __name__ == "__main__":
    app = SecureVaultApp()
    try:
        app.run()
    except KeyboardInterrupt:
        app.db.disconnect()
        print("\n[⚠️] Chương trình bị dừng")
        sys.exit(0)
