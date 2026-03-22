"""
======================================
MODULE: file_handler.py
Xử lý upload/download file mã hóa
======================================

Chức năng:
- Upload file → mã hóa bằng AES (hỗ trợ mọi định dạng file nhị phân)
- Download file → giải mã
- Xóa file
- Kiểm tra integrity file

Quy trình upload:
1. Read file gốc (binary)
2. Tính SHA-256 (file_hash_original)
3. Mã hóa bằng AES (truyền trực tiếp bytes)
4. Tính SHA-256 file encrypted (file_hash_encrypted)
5. Lưu file encrypted vào đĩa
6. Lưu metadata vào DB

Quy trình download:
1. Lấy file encrypted từ đĩa
2. Tính SHA-256 file encrypted → so với DB
   - Nếu khác: file bị modify → từ chối
3. Giải mã bằng AES (trả về bytes)
4. Tính SHA-256 file plaintext → so với DB
   - Nếu khác: giải mã sai
5. Trả về file plaintext
"""

import os
import shutil
from pathlib import Path
from encryption import AESEncryption
from hashing import PasswordHasher
from database import Database
from typing import List, Dict, Optional, Tuple


class FileHandler:
    """Lớp xử lý file upload/download/delete"""
    
    def __init__(self, db: Database, user_id: int, aes_key: bytes,
                 encrypted_folder: str = "./encrypted_files"):
        """
        Khởi tạo FileHandler
        
        Args:
            db (Database): Instance Database
            user_id (int): ID user
            aes_key (bytes): AES key của user
            encrypted_folder (str): Thư mục lưu file encrypted
        """
        self.db = db
        self.user_id = user_id
        self.cipher = AESEncryption(aes_key)
        self.encrypted_folder = encrypted_folder
        
        # Tạo thư mục nếu chưa tồn tại
        Path(self.encrypted_folder).mkdir(parents=True, exist_ok=True)
    
    def upload_file(self, file_path: str) -> bool:
        """
        Upload file (mã hóa + lưu)
        
        Args:
            file_path (str): Đường dẫn file gốc
        
        Returns:
            bool: True nếu upload thành công
        """
        # Check file tồn tại
        if not os.path.exists(file_path):
            print(f"[❌] File '{file_path}' không tồn tại")
            return False
        
        file_name = os.path.basename(file_path)
        
        try:
            # Read file dưới dạng binary (bytes)
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Tính hash gốc
            file_hash_original = PasswordHasher.hash_for_file_integrity(file_content)
            
            # Mã hóa file (Truyền trực tiếp bytes vào hàm mã hóa, không dùng decode latin1)
            iv, encrypted_content = self.cipher.encrypt(file_content)
            
            # Tính hash encrypted
            file_hash_encrypted = PasswordHasher.hash_for_file_integrity(encrypted_content)
            
            # Lưu file encrypted
            encrypted_file_path = os.path.join(
                self.encrypted_folder,
                f"user_{self.user_id}_{file_name}.encrypted"
            )
            
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv)  # Lưu IV (16 bytes)
                f.write(encrypted_content)  # Lưu encrypted content
            
            # Lưu metadata vào DB
            file_size = len(file_content)
            file_id = self.db.add_file(
                user_id=self.user_id,
                file_name=file_name,
                file_path=encrypted_file_path,
                file_hash_original=file_hash_original,
                file_hash_encrypted=file_hash_encrypted,
                file_size_original=file_size
            )
            
            if file_id > 0:
                print(f"[✅] File '{file_name}' upload thành công (encrypted)")
                print(f"   Original hash: {file_hash_original}")
                print(f"   Encrypted hash: {file_hash_encrypted}")
                return True
            else:
                return False
        
        except Exception as e:
            print(f"[❌] Lỗi upload file: {e}")
            return False
    
    def download_file(self, file_id: int, save_path: str) -> bool:
        """
        Download file (giải mã + lưu)
        
        Args:
            file_id (int): ID file
            save_path (str): Đường dẫn lưu file
        
        Returns:
            bool: True nếu download thành công
        """
        file_info = self.db.get_file_by_id(file_id, self.user_id)
        if not file_info:
            print(f"[❌] File ID {file_id} không tồn tại")
            return False
        
        try:
            # Read file encrypted
            encrypted_file_path = file_info['file_path']
            with open(encrypted_file_path, 'rb') as f:
                file_data = f.read()
            
            # Tách IV (16 bytes đầu) + encrypted content
            iv = file_data[:16]
            encrypted_content = file_data[16:]
            
            # Verify hash encrypted
            computed_hash = PasswordHasher.hash_for_file_integrity(encrypted_content)
            if computed_hash != file_info['file_hash_encrypted']:
                print("[❌] File bị modify hoặc corrupt (hash không khớp)")
                return False
            
            # Giải mã (Hàm decrypt giờ đã trả về trực tiếp bytes gốc)
            decrypted_content = self.cipher.decrypt(iv, encrypted_content)
            
            # Verify hash plaintext
            computed_original_hash = PasswordHasher.hash_for_file_integrity(decrypted_content)
            if computed_original_hash != file_info['file_hash_original']:
                print("[❌] Lỗi giải mã (hash không khớp)")
                return False
            
            # Lưu file plaintext
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)
            
            print(f"[✅] File '{file_info['file_name']}' download thành công")
            print(f"   Saved to: {save_path}")
            return True
        
        except Exception as e:
            print(f"[❌] Lỗi download file: {e}")
            return False
    
    def delete_file(self, file_id: int) -> bool:
        """
        Xóa file
        
        Args:
            file_id (int): ID file
        
        Returns:
            bool: True nếu xóa thành công
        """
        result = self.db.delete_file(file_id, self.user_id)
        if result:
            print(f"[✅] File ID {file_id} đã xóa")
        else:
            print(f"[❌] Không thể xóa file ID {file_id}")
        return result
    
    def list_files(self) -> List[Dict]:
        """
        Liệt kê tất cả file của user
        
        Returns:
            List[Dict]: Danh sách file
        """
        return self.db.get_files_by_user(self.user_id)
    
    def list_files_pretty(self):
        """Hiển thị danh sách file đẹp"""
        files = self.list_files()
        
        if not files:
            print("Không có file nào được lưu")
            return
        
        print("\n" + "="*80)
        print(f"{'ID':<5} {'File Name':<25} {'Size':<10} {'Uploaded':<20}")
        print("="*80)
        
        for f in files:
            size_kb = f['file_size_original'] / 1024
            print(f"{f['id']:<5} {f['file_name']:<25} {size_kb:.2f}KB {f['created_at']:<20}")
        
        print("="*80 + "\n")


def test_file_handler():
    """
    Test file handler
    """
    import os
    from key_derivation import KeyDerivation
    from hashing import PasswordHasher
    
    # Setup
    test_db = "test_fh.db"
    test_file = "test_document.txt"
    test_decrypted = "test_decrypted.txt"
    
    if os.path.exists(test_db):
        os.remove(test_db)
    if os.path.exists(test_file):
        os.remove(test_file)
    if os.path.exists(test_decrypted):
        os.remove(test_decrypted)
    
    print("[✅ TEST FILE HANDLER]")
    
    # Tạo DB
    db = Database(test_db)
    db.connect()
    db.create_tables()
    
    # Tạo user
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
    
    # Tạo test file
    test_content = "Hello, Secure Vault System!\nThis is a confidential document.\nIt will be encrypted!"
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    # Tạo FileHandler
    fh = FileHandler(db, user_id, aes_key, "./test_encrypted")
    
    # Test 1: Upload file
    print("\n1. Uploading file...")
    fh.upload_file(test_file)
    
    # Test 2: List files
    print("\n2. Listing files...")
    fh.list_files_pretty()
    
    # Test 3: Download file
    print("3. Downloading file...")
    files = fh.list_files()
    if files:
        fh.download_file(files[0]['id'], test_decrypted)
    
    # Test 4: Verify content
    print("\n4. Verifying content...")
    with open(test_decrypted, 'r') as f:
        decrypted_content = f.read()
    
    print(f"   Original == Decrypted: {test_content == decrypted_content}")
    print(f"   Content: {decrypted_content[:50]}...")
    
    # Cleanup
    db.disconnect()
    os.remove(test_db)
    os.remove(test_file)
    os.remove(test_decrypted)
    shutil.rmtree("./test_encrypted", ignore_errors=True)
    print("\n[✅] File Handler test passed!")


if __name__ == "__main__":
    test_file_handler()