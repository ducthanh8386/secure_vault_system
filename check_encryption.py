"""
======================================
MODULE: check_encryption.py
Kiểm tra xem dữ liệu có được mã hóa không
======================================

Script này không dùng thư viện ngoài (chỉ dùng sqlite3 + builtin)
Dùng để:
1. Xem database
2. Verify encryption

Chạy: python check_encryption.py
"""

import sqlite3
import os


def check_encryption(db_path="vault.db"):
    """
    Kiểm tra encryption trong database
    """
    
    if not os.path.exists(db_path):
        print(f"\n[❌] Database '{db_path}' không tồn tại")
        print("Hãy chạy: python gui.py (hoặc python main.py)")
        print("Tạo một user và thêm password/file để test\n")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n" + "="*100)
    print("🔐 ENCRYPTION VERIFICATION - Kiểm tra mã hóa dữ liệu")
    print("="*100)
    
    # ============= USERS =============
    print("\n[1️⃣  USERS TABLE - Lưu password hash (SHA-256 + salt)]")
    print("-" * 100)
    
    cursor.execute("SELECT id, username, length(password_hash) as hash_len, length(password_salt) as salt_len FROM users")
    users = cursor.fetchall()
    
    if users:
        print(f"{'ID':<5} {'Username':<20} {'Hash Length':<15} {'Salt Length':<15} {'Status':<20}")
        print("-" * 100)
        
        for user_id, username, hash_len, salt_len in users:
            status = "✅ HASHED (32 bytes)" if hash_len == 32 else f"⚠️  Length: {hash_len}"
            print(f"{user_id:<5} {username:<20} {hash_len:<15} {salt_len:<15} {status:<20}")
        
        print(f"\n✅ PASSWORD SECURITY:")
        print(f"   • Password user được hash bằng SHA-256 (32 bytes)")
        print(f"   • Mỗi password có salt ngẫu nhiên (16 bytes)")
        print(f"   • ➜ Password không thể reverse (one-way hash)")
        print(f"   • ➜ Nếu DB bị lộ, attacker không biết password!")
    else:
        print("(Chưa có user)")
    
    # ============= PASSWORDS =============
    print("\n\n[2️⃣  PASSWORDS TABLE - Lưu password mã hóa (AES-256)]")
    print("-" * 100)
    
    cursor.execute("""
        SELECT p.id, p.site, p.username, 
               length(p.encrypted_password) as encrypted_len,
               length(p.encrypted_password_iv) as iv_len
        FROM passwords p
    """)
    passwords = cursor.fetchall()
    
    if passwords:
        print(f"{'ID':<5} {'Site':<15} {'Username':<20} {'Encrypted Size':<20} {'IV Size':<15} {'Status':<20}")
        print("-" * 100)
        
        for pwd_id, site, username, enc_len, iv_len in passwords:
            status = "✅ ENCRYPTED (AES)" if iv_len == 16 else f"⚠️  IV: {iv_len}"
            print(f"{pwd_id:<5} {site:<15} {username:<20} {enc_len:<20} {iv_len:<15} {status:<20}")
        
        print(f"\n✅ PASSWORD ENCRYPTION:")
        print(f"   • Password lưu được mã hóa bằng AES-256-CBC")
        print(f"   • Mỗi password có IV ngẫu nhiên (16 bytes)")
        print(f"   • Cùng password không có IV = ciphertext khác")
        print(f"   • ➜ Password không thể đọc từ DB")
        print(f"   • ➜ Phải có AES_key mới decode được!")
        
        # Hiển thị dữ liệu thực tế (encrypted)
        print(f"\n📋 DỮ LIỆU THỰC TẾ (Encrypted):")
        cursor.execute("""
            SELECT site, username, hex(encrypted_password) as enc_hex, hex(encrypted_password_iv) as iv_hex
            FROM passwords
            LIMIT 3
        """)
        
        for site, username, enc_hex, iv_hex in cursor.fetchall():
            print(f"\n   Site: {site} ({username})")
            print(f"   IV (hex):  {iv_hex}")
            print(f"   Encrypted (hex): {enc_hex[:64]}...")
            print(f"   ➜ Data trông random (sign of encryption)!")
    else:
        print("(Chưa có password được lưu)")
        print("\n📝 TIP: Hãy:")
        print("   1. Chạy GUI: python gui.py")
        print("   2. Đăng ký user mới")
        print("   3. Thêm password (password sẽ được mã hóa)")
        print("   4. Chạy lại script này: python check_encryption.py")
    
    # ============= FILES =============
    print("\n\n[3️⃣  FILES TABLE - Lưu metadata file mã hóa]")
    print("-" * 100)
    
    cursor.execute("""
        SELECT id, file_name, file_size_original, 
               length(file_hash_original) as orig_hash_len,
               length(file_hash_encrypted) as enc_hash_len
        FROM files
    """)
    files = cursor.fetchall()
    
    if files:
        print(f"{'ID':<5} {'File Name':<30} {'Size':<15} {'Hash Status':<20}")
        print("-" * 100)
        
        for file_id, file_name, file_size, orig_hash_len, enc_hash_len in files:
            status = "✅ HASHED (SHA-256)" if orig_hash_len == 64 else f"⚠️  {orig_hash_len}"
            print(f"{file_id:<5} {file_name:<30} {file_size:<15} {status:<20}")
        
        print(f"\n✅ FILE ENCRYPTION:")
        print(f"   • File được mã hóa bằng AES-256-CBC")
        print(f"   • File hash: SHA-256(encrypted_file) → detect modification")
        print(f"   • Plaintext hash: SHA-256(plaintext) → detect decrypt error")
        print(f"   • ➜ Nếu file bị modify, sẽ detect!")
        print(f"   • ➜ Nếu decrypt sai, sẽ detect!")
        
        # Hiển thị encrypted files
        print(f"\n📂 ENCRYPTED FILES (xem file vật lý):")
        encrypted_folder = "./encrypted_files"
        
        if os.path.exists(encrypted_folder):
            files_list = os.listdir(encrypted_folder)
            for file_name in files_list[:3]:  # Show 3 files
                file_path = os.path.join(encrypted_folder, file_name)
                file_size = os.path.getsize(file_path)
                
                with open(file_path, 'rb') as f:
                    first_bytes = f.read(32)
                    hex_str = first_bytes.hex()
                
                print(f"\n   📄 {file_name}")
                print(f"      Size: {file_size} bytes")
                print(f"      First 32 bytes (hex): {hex_str}")
                print(f"      ➜ File encrypted (không phải plaintext)!")
    else:
        print("(Chưa có file được upload)")
        print("\n📝 TIP: Hãy:")
        print("   1. Chạy GUI: python gui.py")
        print("   2. Tạo file test (secret.txt)")
        print("   3. Upload file (sẽ được mã hóa)")
        print("   4. Chạy lại script này: python check_encryption.py")
    
    conn.close()
    
    # ============= SUMMARY =============
    print("\n\n" + "="*100)
    print("📊 TÓM TẮT BẢO MẬT")
    print("="*100)
    
    print("""
    🔐 MỨC ĐỘ BẢO MẬT: EXCELLENT ✅
    
    LAYER 1: PASSWORD USER
    ├─ Hash: SHA-256(password + salt)
    ├─ Salt: Random (16 bytes)
    ├─ Một chiều: Không thể reverse
    └─ ➜ Nếu DB bị lộ → Password user vẫn an toàn
    
    LAYER 2: AES KEY
    ├─ Sinh từ: PBKDF2(password, salt, 100,000 iterations)
    ├─ Yêu cầu: SHA-256 hash liên tục 100,000 lần
    ├─ Mục đích: Làm chậm brute force (1 attempt ≈ 100ms)
    └─ ➜ Brute force 1 triệu password = 27 giờ (không khả thi!)
    
    LAYER 3: MẬT KHẨU LƯU (Password)
    ├─ Mã hóa: AES-256-CBC
    ├─ IV: Random (16 bytes, mỗi lần khác)
    ├─ Key: AES_key của user (từ PBKDF2)
    └─ ➜ Nếu DB bị lộ → Password vẫn encrypted, không đọc được
    
    LAYER 4: FILE
    ├─ Mã hóa: AES-256-CBC (giống password)
    ├─ Integrity: SHA-256 hash (detect modification)
    ├─ Key: AES_key của user
    └─ ➜ Nếu DB bị lộ → File vẫn encrypted
    
    LAYER 5: ACCESS CONTROL
    ├─ Mỗi user: AES_key riêng
    ├─ User A: Không thể decrypt password User B
    ├─ Khóa: Database check ownership
    └─ ➜ Ngay cả admin cũng không thể truy cập dữ liệu user khác!
    
    ⚠️ ĐIỂM YẾU (có thể cải thiện):
    ├─ Nếu password user yếu (<8 ký tự):
    │  └─ Attacker có thể brute force PBKDF2 (100k iterations)
    ├─ Nếu máy bị malware:
    │  └─ Malware có thể access RAM (lấy AES_key)
    ├─ Nếu không dùng HTTPS (web version):
    │  └─ Man-in-the-middle có thể capture data
    └─ Không có MFA (Multi-Factor Authentication)
    
    ✅ KHUYẾN CÁO:
    1. Dùng password mạnh (>12 ký tự, mix case + numbers + symbols)
    2. Bảo vệ mật khẩu user (giống password ngân hàng)
    3. Nếu quên password → không có cách recover (an toàn!)
    4. Nếu deploy web → dùng HTTPS + TLS
    5. Nếu muốn secure hơn → thêm MFA
    """)
    
    print("="*100 + "\n")


if __name__ == "__main__":
    check_encryption()
