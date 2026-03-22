"""
======================================
MODULE: gui.py
Giao diện đồ họa (GUI) cho Secure Vault System
======================================
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import os
import tempfile
import platform
import subprocess
from database import Database
from auth import AuthManager
from password_manager import PasswordManager
from file_handler import FileHandler


# ============= COLOR SCHEME =============
COLOR_BG = "#0d1117"
COLOR_FG = "#c9d1d9"
COLOR_ACCENT = "#1f6feb"
COLOR_ACCENT_HOVER = "#388bfd"
COLOR_SUCCESS = "#238636"
COLOR_ERROR = "#da3633"
COLOR_WARNING = "#bf8700"


class SecureVaultGUI:
    """GUI cho Secure Vault System"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Vault System")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Setup
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root.configure(fg_color=COLOR_BG)
        
        # Database
        self.db = Database("vault.db")
        self.db.connect()
        self.db.create_tables()
        
        # Auth
        self.auth = AuthManager(self.db)
        self.password_manager = None
        self.file_handler = None
        
        # State
        self.current_frame = None
        
        # Show login screen
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
        info = ctk.CTkLabel(info_frame, text=info_text.strip(), font=("Helvetica", 12), text_color=COLOR_FG, justify="left")
        info.pack(padx=20, pady=20)
    
    def show_login_form(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        container = ctk.CTkFrame(self.current_frame, fg_color="#161b22", corner_radius=15)
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        title = ctk.CTkLabel(container, text="ĐĂNG NHẬP", font=("Helvetica", 24, "bold"), text_color=COLOR_ACCENT)
        title.pack(pady=20)
        
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
        
        title = ctk.CTkLabel(container, text="ĐĂNG KÝ", font=("Helvetica", 24, "bold"), text_color=COLOR_ACCENT)
        title.pack(pady=20)
        
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
                messagebox.showinfo("Thành công", f"Đăng ký thành công! Vui lòng đăng nhập")
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
        site_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Ví dụ: Gmail, GitHub, Facebook...", corner_radius=8)
        site_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Username:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        user_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập username...", corner_radius=8)
        user_entry.pack(padx=20, pady=(0, 15))
        
        ctk.CTkLabel(container, text="Mật khẩu:", text_color=COLOR_FG).pack(anchor="w", padx=20, pady=(0, 5))
        pwd_entry = ctk.CTkEntry(container, width=300, height=40, placeholder_text="Nhập password...", show="*", corner_radius=8)
        pwd_entry.pack(padx=20, pady=(0, 30))
        
        def save_action():
            site = site_entry.get()
            username = user_entry.get()
            password = pwd_entry.get()
            
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
                
                info_text = f"🌐 {pwd['site']}  |  👤 {pwd['username']}"
                ctk.CTkLabel(pwd_frame, text=info_text, font=("Helvetica", 12), text_color=COLOR_FG).pack(anchor="w", padx=15, pady=(10, 5))
                
                btn_frame = ctk.CTkFrame(pwd_frame, fg_color="#0d1117")
                btn_frame.pack(anchor="w", padx=15, pady=(0, 10))
                
                def view_pwd(pid=pwd['id'], s=pwd['site']):
                    decrypted = self.password_manager.view_password(pid)
                    if decrypted:
                        messagebox.showinfo(f"Password - {s}", f"Password: {decrypted}")
                
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
                info_text = f"📄 {f['file_name']}  |  💾 {size_kb:.2f}KB"
                ctk.CTkLabel(file_frame, text=info_text, font=("Helvetica", 12), text_color=COLOR_FG).pack(anchor="w", padx=15, pady=(10, 5))
                
                btn_frame = ctk.CTkFrame(file_frame, fg_color="#0d1117")
                btn_frame.pack(anchor="w", padx=15, pady=(0, 10))
                
                # --- HÀM XEM FILE TRỰC TIẾP (AN TOÀN) ---
                def view_file_securely(fid=f['id'], fname=f['file_name']):
                    temp_dir = tempfile.mkdtemp()
                    temp_path = os.path.join(temp_dir, fname)
                    
                    # Giải mã file vào thư mục rác (Temp folder)
                    if self.file_handler.download_file(fid, temp_path):
                        try:
                            # Mở file bằng phần mềm mặc định của máy
                            if platform.system() == 'Darwin':       # macOS
                                subprocess.call(('open', temp_path))
                            elif platform.system() == 'Windows':    # Windows
                                os.startfile(temp_path)
                            else:                                   # Linux
                                subprocess.call(('xdg-open', temp_path))
                            
                            # Hiển thị thông báo CHẶN CHƯƠNG TRÌNH
                            messagebox.showinfo(
                                "Đang xem file 👁️",
                                f"Đang xem: '{fname}'.\n\n⚠ BẢO MẬT: Sau khi bạn xem xong và đóng phần mềm bên ngoài, hãy bấm 'OK' ở hộp thoại này để hệ thống xóa triệt để file tạm!"
                            )
                        except Exception as e:
                            messagebox.showerror("Lỗi", f"Không thể mở ứng dụng xem file: {e}")
                        finally:
                            # Xóa file tạm ngay sau khi bấm OK
                            try:
                                if os.path.exists(temp_path):
                                    os.remove(temp_path)
                                if os.path.exists(temp_dir):
                                    os.rmdir(temp_dir)
                            except Exception as e:
                                print(f"Không thể dọn dẹp file tạm (có thể file chưa bị đóng): {e}")
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
                
                # Nút Xem (Mới)
                ctk.CTkButton(btn_frame, text="👀 Xem", width=90, height=30, font=("Helvetica", 10, "bold"), fg_color="#2ea043", hover_color="#238636", command=view_file_securely).pack(side="left", padx=5)
                
                ctk.CTkButton(btn_frame, text="📥 Download", width=90, height=30, font=("Helvetica", 10), fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=download_file).pack(side="left", padx=5)
                ctk.CTkButton(btn_frame, text="🗑️ Xóa", width=80, height=30, font=("Helvetica", 10), fg_color=COLOR_ERROR, hover_color="#b62324", command=delete_file).pack(side="left", padx=5)
    
    def show_info(self):
        self.clear_frame()
        self.current_frame = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        self.current_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(self.current_frame, fg_color="#161b22", height=60)
        header.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(header, text="ℹ️ THÔNG TIN HỆ THỐNG", font=("Helvetica", 18, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(header, text="← Quay Lại", width=100, height=40, font=("Helvetica", 11), fg_color="#333", hover_color="#444", command=self.show_dashboard).pack(side="right", padx=20, pady=10)
        
        content = ctk.CTkScrollableFrame(self.current_frame, fg_color="#161b22", corner_radius=10)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        passwords = self.password_manager.get_passwords()
        files = self.file_handler.list_files()
        
        info_text = f"👤 THÔNG TIN NGƯỜI DÙNG\nUsername: {self.auth.current_username}\nUser ID: {self.auth.current_user_id}\n\n📊 THỐNG KÊ\nPassword lưu: {len(passwords)}\nFile lưu: {len(files)}\n\n🔐 BẢO MẬT\n✅ Password User: SHA-256 + salt\n✅ AES Key Derivation: PBKDF2 (100,000 iterations)\n✅ Password Lưu: AES-256-CBC mã hóa\n✅ File: AES-256-CBC mã hóa + SHA-256 integrity\n✅ Access Control: Mỗi user key riêng\n\n🛡️ MƯỚC ĐỘ BẢO MẬT: EXCELLENT\nNếu database bị lộ → dữ liệu vẫn mã hóa\nNếu password user mạnh → attacker không thể crack AES key"
        ctk.CTkLabel(content, text=info_text.strip(), font=("Helvetica", 12), text_color=COLOR_FG, justify="left").pack(padx=20, pady=20, fill="both", expand=True)
    
    def logout(self):
        self.auth.logout()
        self.password_manager = None
        self.file_handler = None
        self.show_login_screen()
    
    def on_closing(self):
        self.db.disconnect()
        self.root.destroy()

def main():
    root = ctk.CTk()
    app = SecureVaultGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()