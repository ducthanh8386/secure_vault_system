# 🔐 SECURITY GUIDE - Hướng dẫn bảo mật chi tiết

> **Tài liệu này giải thích các kỹ thuật bảo mật đã dùng trong Secure Vault System**

---

## 📚 Mục lục

1. [Cryptographic basics](#cryptographic-basics)
2. [Password hashing](#password-hashing)
3. [Data encryption](#data-encryption)
4. [Key derivation](#key-derivation)
5. [Integrity checking](#integrity-checking)
6. [Attack scenarios](#attack-scenarios)
7. [Best practices](#best-practices)
8. [Limitations](#limitations)

---

## Cryptographic Basics

### Hash Function (Hàm Băm)

**Định nghĩa:**
- Chuyển input (bất kỳ kích thước) → output cố định
- Một chiều: không thể reverse (plaintext → hash ok, hash → plaintext ❌)
- Không va chạm: hai input khác nhau → hash khác nhau

**Ví dụ:**
```
SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA-256("Hello") = 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
```

**Ứng dụng:**
- Verifying password
- File integrity checking
- Digital signatures

**Tại sao SHA-256?**
- NIST chuẩn
- 256-bit output (2^256 ≈ 10^77 khả năng)
- Hiệu suất tốt
- Collision resistant

---

## Password Hashing

### Vấn đề: Plaintext Password

**❌ SAI CÁCH:**
```python
# Database schema (WRONG!)
users = {
    "alice": "MyPassword123",   # ← Plaintext!
    "bob": "BobPassword456"
}

# Nếu DB bị lộ:
# → Hacker biết tất cả password
```

**Nguy hiểm:**
- Nếu DB bị lộ → User compromised
- Hacker có thể tấn công các site khác (nếu user dùng lại password)
- Không có bảo vệ

### Giải pháp: Hash Password

**✅ ĐÚNG CÁCH:**
```python
# Database schema (CORRECT!)
users = {
    "alice": {
        "password_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "salt": "random16bytes..."
    },
    "bob": {
        "password_hash": "...",
        "salt": "..."
    }
}

# Nếu DB bị lộ:
# → Hacker chỉ có hash
# → Không thể tìm được plaintext password
```

**Verify password:**
```python
# Login
user_input = "MyPassword123"
stored_hash = users["alice"]["password_hash"]
stored_salt = users["alice"]["salt"]

# Hash lại user input
computed_hash = SHA256(user_input + stored_salt)

# Compare
if computed_hash == stored_hash:
    ✅ LOGIN SUCCESS
else:
    ❌ LOGIN FAILED
```

### Salt - Ngăn chặn Rainbow Table Attack

**Rainbow Table Attack:**
- Pre-compute hash của tất cả password phổ biến
- Lưu vào bảng (rainbow table)
- Nếu DB bị lộ, so sánh hash → tìm password

**Ví dụ:**
```
Rainbow Table:
  hash: password
  5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 : password
  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 : hello
  ...
  
Database bị lộ:
  alice: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
  
Hacker tra bảng:
  ✅ Tìm được: password = "password"
```

**Salt ngăn chặn:**
```
Salt = random(16 bytes)
hash = SHA256(password + salt)  ← salt khác nhau

Cùng password "password":
  Alice:
    salt1 = "abc123..."
    hash1 = SHA256("password" + "abc123...")
  
  Bob:
    salt2 = "xyz789..."
    hash2 = SHA256("password" + "xyz789...")
  
  hash1 ≠ hash2  ← Khác nhau!
  
Rainbow table không dùng được:
  cần phải pre-compute mọi salt × mọi password
  = 2^128 × 10^9 = không khả thi
```

### Timing Attack - Ngăn chặn

**Timing Attack:**
- So sánh password character by character
- Nếu character 1 sai → return ngay (1ms)
- Nếu character 1 đúng, character 2 sai → return sau (2ms)
- Hacker có thể đoán password bằng timing

**Giải pháp:**
```python
# ❌ SẠNG:
if password == correct_password:
    # Time khác nhau tuỳ theo khi nào match fail
    return True

# ✅ ĐÚNG:
# Use constant-time comparison
import hmac
if hmac.compare_digest(password_hash, computed_hash):
    # Luôn mất cùng thời gian
    return True
```

**Secure Vault System:**
Bài này sử dụng `==` để đơn giản hóa. Ứng dụng production nên dùng `hmac.compare_digest()`.

---

## Data Encryption

### Symmetric Encryption (Mã hóa đối xứng)

**Định nghĩa:**
- Dùng chung 1 key để encrypt/decrypt
- Hai chiều: plaintext ↔ ciphertext

**Ví dụ:**
```
key = "SecretKey"
plaintext = "Hello, World!"
ciphertext = AES_encrypt(plaintext, key)
            = "1a2b3c4d..."

plaintext = AES_decrypt(ciphertext, key)
          = "Hello, World!"
```

**Ngược lại với hash:**
```
hash = SHA256("Secret") = "abc123..."
❌ Không thể: hash_decrypt() - không tồn tại!
```

### Tại sao dùng AES thay vì hash?

| Yêu cầu | Hash | AES | Chọn |
|---------|------|-----|------|
| Lưu password có thể lấy lại | ❌ | ✅ | AES |
| Lưu file có thể đọc lại | ❌ | ✅ | AES |
| Bảo vệ password user | ✅ | ❌ | Hash |
| Kiểm tra integrity | ✅ | ❌ | Hash |

**Ví dụ:**
```python
# Password User Alice
password_user = "MyPassword123"
password_hash = SHA256(password_user + salt)  # ← Hash
lưu: password_hash
# Không thể lấy lại password user → Dùng hash đúng!

# Password Gmail của Alice
password_gmail = "GmailPassword123!"
aes_key = PBKDF2(password_user, salt2)
encrypted_pwd = AES_encrypt(password_gmail, aes_key)  # ← AES
lưu: encrypted_pwd, IV
# Phải lấy được password Gmail → Dùng AES đúng!
```

### AES-256 (Advanced Encryption Standard)

**Tham số:**
- **Key size:** 256-bit = 32 bytes
- **Block size:** 128-bit = 16 bytes
- **Mode:** CBC (Cipher Block Chaining)
- **Padding:** PKCS7 (tự động)

**Tại sao 256-bit?**
- 2^256 ≈ 1.1 × 10^77 khả năng
- Brute force: không khả thi (thậm chí với tất cả máy trên Trái Đất)
- 128-bit (AES-128): still secure, nhưng 256-bit better for future-proofing

**Tại sao CBC mode?**
- Mỗi block tergantung block trước
- Cùng plaintext, plaintext khác IV → ciphertext khác
- Ngăn chặn pattern analysis attack

**Ví dụ:**
```python
plaintext = "AAAAAAAAAAAAAAAA"  # 16 As (1 block)
key = ...
iv1 = random(16 bytes)
iv2 = random(16 bytes)

ciphertext1 = AES_encrypt(plaintext, key, iv1) = "xyz..."
ciphertext2 = AES_encrypt(plaintext, key, iv2) = "abc..."

ciphertext1 ≠ ciphertext2  ← Khác, do IV khác!
```

### IV (Initialization Vector)

**Là gì:**
- Random 16-byte value (cho AES)
- Dùng để "xáo trộn" plaintext trước khi encrypt

**Tại sao cần:**
- Ngăn chặn ECB mode (Electronic Codebook) - insecure
- Cung cấp non-deterministic encryption

**ECB (❌ SAI):**
```
Cùng block plaintext → cùng cipher block (mô hìnhì bị lộ)
```

**CBC (✅ ĐÚNG):**
```
IV xáo trộn plaintext → cipher block khác nhau
```

**IV không cần bảo mật:**
- IV có thể lưu cùng với ciphertext
- Nhưng phải random (không dự đoán được)
- Mỗi lần encrypt → IV mới

**Secure Vault System:**
```python
plaintext = "password123"
iv = os.urandom(16)  # ← Random
ciphertext = AES_encrypt(plaintext, iv, key)

# Lưu vào DB:
lưu: (IV, ciphertext)  # ← Cả hai lưu

# Giải mã:
plaintext = AES_decrypt(ciphertext, iv, key)  # ← Dùng IV
```

---

## Key Derivation

### Vấn đề: Password không phải AES key

**Password user:**
- "MyPassword" = 10 bytes
- Có thể < 32 bytes, không đủ cho AES-256

**AES key:**
- Cần đúng 32 bytes (256-bit)
- Cần random (password không random)

**❌ SAI CÁCH:**
```python
password = "MyPassword"
# Padding để 32 bytes:
aes_key = password.ljust(32, '\0')  # ← Yếu!
# "MyPassword\0\0\0\0..."
# Hacker biết phần password, có thể brute force
```

### Giải pháp: PBKDF2 (Password-Based Key Derivation Function 2)

**PBKDF2 công thức:**
```
key = PBKDF2(
    password = user_password,
    salt = random,
    iterations = N (100,000),
    output_length = 32 bytes,
    hash_algorithm = SHA-256
)
```

**Quá trình:**
```
Iteration 1: hash = SHA256(password + salt)
Iteration 2: hash = SHA256(hash + salt)
...
Iteration 100,000: hash = SHA256(hash + salt)

Output: 32 bytes → dùng as AES key
```

**Tại sao làm chậm?**

**Brute force attack:**
```
Scenario: Hacker có DB + biết salt
Muốn crack AES key

Nếu không dùng PBKDF2:
  hash = SHA256(password)  # ← 1μs (microsecond)
  Brute force 1 triệu passwords = 1 giây
  ✅ Khả thi!

Nếu dùng PBKDF2 (100k iterations):
  key = PBKDF2(password, salt, 100k)  # ← 100ms
  Brute force 1 triệu passwords = 100,000 giây ≈ 1.2 ngày
  ❌ Không khả thi!
```

**Chọn iterations bao nhiêu?**
- NIST khuyến nghị: 100,000 - 200,000
- Trade-off: bảo mật vs hiệu năng
- Mỗi năm nên tăng (do máy tính nhanh lên)

---

## Integrity Checking

### Vấn đề: File có bị thay đổi không?

**Scenario:**
```
1. Alice upload file "secret.txt"
   File được encrypt → lưu vào đĩa
   
2. Hacker truy cập đĩa
   Sửa file (modify bits), re-encrypt sai
   
3. Alice download file
   Decrypt → nhận file sai
   ❌ Không biết được file bị modify!
```

### Giải pháp: Hash-based Integrity Check

**MAC (Message Authentication Code):**
```python
# Upload
file_content = read(file)
hash_original = SHA256(file_content)  # ← Tính hash

encrypt_content = AES_encrypt(file_content)
hash_encrypted = SHA256(encrypt_content)  # ← Hash encrypted

lưu: (hash_original, hash_encrypted, IV, encrypt_content)

# Download
encrypt_content = read_from_disk()
hash_encrypted_computed = SHA256(encrypt_content)

if hash_encrypted_computed ≠ hash_encrypted_DB:
    ❌ FILE BỊ MODIFY!
    return

decrypt_content = AES_decrypt(encrypt_content, IV)
hash_original_computed = SHA256(decrypt_content)

if hash_original_computed ≠ hash_original_DB:
    ❌ DECRYPT SAI!
    return

✅ FILE OK
```

**Tại sao 2 hash?**
- Hash encrypted: detect file bị modify trước khi decrypt
- Hash original: detect decrypt sai hoặc file corrupt

---

## Attack Scenarios

### 1. Rainbow Table Attack

**Attacker has:** DB with password hashes (no salt)

**Attack:**
```
rainbow_table = {
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "password",
    "81dc9bdb52d04dc20036dbd8313ed055": "123",
    ...
}

db_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

password = rainbow_table.get(db_hash)  # → "password"
```

**Defense (Secure Vault System):**
- ✅ Sử dụng salt
- Hash = SHA256(password + salt)
- Không thể pre-compute rainbow table (quá lớn)

### 2. Brute Force Attack on PBKDF2

**Attacker has:** DB + knows salt

**Attack:**
```python
for password in wordlist:
    derived_key = PBKDF2(password, salt, 100k)
    if derived_key matches DB:
        ✅ Found password!
```

**How long:**
```
Wordlist size: 1 triệu password
PBKDF2 time: 100ms mỗi attempt
Total time: 100,000 giây ≈ 1.2 ngày

❌ Không khả thi cho mass cracking
(nhưng single password có khả thi)
```

**Defense:**
- ✅ Use strong password (>12 characters, mixed case + numbers + symbols)
- ✅ Increase iterations nếu có thể (200k, 300k)

### 3. AES-256 Brute Force

**Attacker has:** Ciphertext + IV (không có key)

**Attack:**
```python
for key in range(2^256):  # 10^77 khả năng
    plaintext = AES_decrypt(ciphertext, IV, key)
    if valid_plaintext(plaintext):  # ← Check format
        ✅ Found key!
```

**Thời gian:**
```
Máy tính: 1 GHz (10^9 operations/second)
Brute force: 2^256 / 10^9 = 10^68 giây
           ≈ 10^60 năm

❌ Không khả thi!
(thậm chí với tất cả máy trên Trái Đất)
```

**Defense:**
- ✅ AES-256 an toàn từ brute force
- Attack: phải tấn công key derivation (PBKDF2) thay vì key

### 4. Access Control Bypass

**Scenario:**
```
User A (id=1) muốn truy cập data User B (id=2)

Database:
  passwords table:
    id | user_id | encrypted_pwd | ...
    1  | 1       | AES_encrypted | ...
    2  | 2       | AES_encrypted | ...
```

**Attack:**
```python
# User A có AES_key của mình = K_A
ciphertext_B = db.get_password(id=2)

# Thử decrypt bằng K_A:
plaintext = AES_decrypt(ciphertext_B, IV, K_A)
# ❌ Gibberish (không match expected format)
```

**Why nó không thành công:**
- User B's AES key = K_B ≠ K_A
- Decrypt với wrong key → gibberish
- Không thể detect xem plaintext valid hay không

**Defense (Secure Vault System):**
- ✅ Database check ownership:
  ```python
  db.get_password(password_id, user_id)
  # ← Verify password belongs to user
  ```

### 5. Offline Dictionary Attack

**Attacker has:** DB (password_hash, salt)

**Attack:**
```python
wordlist = ["password", "123456", "admin", ...]

for password in wordlist:
    hash = SHA256(password + salt)
    if hash == db_hash:
        ✅ Found!
```

**How strong is it:**
```
Wordlist (common passwords): 10 triệu
Time per hash: 1ns
Total time: 10 triệu × 1ns = 10ms

❌ Với user mạnh (>12 char): không có trong wordlist
✅ Với user yếu (<8 char): sẽ bị crack nhanh
```

**Defense:**
- ✅ Enforce strong password requirement
- ✅ Use slow hash (PBKDF2 for password user? - trade-off)

---

## Best Practices

### 1. Password Requirements

**Minimum requirements:**
```
Length: >= 8 characters (12+ recommended)
Complexity: Mix of:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Special characters (!@#$%^&*)
```

**Example good passwords:**
- ✅ MySecure!Pass123
- ✅ coffee#Maker2024
- ❌ password (yếu)
- ❌ 12345678 (yếu)

### 2. Key Management

**Do:**
- ✅ Generate keys cryptographically secure (os.urandom)
- ✅ Store keys separately from plaintext data
- ✅ Use key derivation for password-based keys
- ✅ Rotate keys periodically

**Don't:**
- ❌ Hardcode keys in code
- ❌ Use predictable seeds
- ❌ Store password próximo key
- ❌ Reuse keys across systems

### 3. Secure Deletion

**Data deletion:**
```python
# ❌ SAI:
os.remove(file)  # ← Chỉ xóa reference, data còn trên đĩa!

# ✅ ĐÚNG:
# Overwrite data trước khi xóa
with open(file, 'w') as f:
    f.write('\0' * file_size)
os.remove(file)
```

### 4. Error Handling

**Do:**
- ✅ Generic error messages ("Invalid username or password")
- ✅ Log errors securely
- ✅ Avoid leaking system details

**Don't:**
- ❌ "User not found" (reveals username exists)
- ❌ "Password wrong" (vs generic)
- ❌ Stack traces to users

### 5. Transport Security

**Secure Vault System - CLI:** Don't need (local)

**If deploying as web app:**
- ✅ Use HTTPS (SSL/TLS)
- ✅ Encrypt in transit (even over HTTPS, add app-level encryption)
- ✅ Use secure cookies (HttpOnly, Secure, SameSite flags)

---

## Limitations

### 1. Password User Compromise

**If user's password is leaked:**
```
password_user = "MyPassword"
AES_key = PBKDF2(password_user, salt)
All encrypted data can be decrypted!
```

**Mitigation:**
- User must change password immediately
- Re-encrypt all data with new key
- (This app doesn't implement password change - future feature)

### 2. Malware on Client

**If user's machine is compromised:**
```
Malware can:
- Keylog password
- Access AES_key in RAM
- Steal files
- Inject fake password manager
```

**Mitigation:**
- Keep machine clean (antivirus)
- Use hardware security modules (HSM)
- Multi-factor authentication (MFA)

### 3. Database Compromise

**If server/storage is breached:**
```
Attacker has: DB + encrypted files
BUT: Attacker doesn't have AES_key
  (AES_key only in user's RAM during session)

So: Attacker cannot decrypt data
UNLESS: Attacker also has user's password
```

**Mitigation:**
- Secure server (firewall, access control)
- Regular backups + encryption
- Intrusion detection

### 4. SQL Injection (Simplified App)

**This app doesn't validate SQL carefully:**
```python
# Vulnerable:
db.execute(f"SELECT * FROM users WHERE username='{username}'")
```

**Mitigation (for production):**
- Use parameterized queries (app already does this ✅)
- Input validation
- Least privilege for DB user

### 5. No Multi-Factor Authentication (MFA)

**2FA/MFA adds extra layer:**
```
Login:
  1. Username + password
  2. + One-time code (SMS, authenticator app)
```

**This app:** Single factor (password only)

**Add MFA:** Future enhancement

---

## Conclusion

Secure Vault System demonstrates:

| Concept | Implementation | Security Level |
|---------|-----------------|-----------------|
| Password storage | SHA-256 + salt | 🟢 Good |
| Data encryption | AES-256-CBC | 🟢 Excellent |
| Key derivation | PBKDF2 (100k) | 🟢 Good |
| Integrity check | SHA-256 hash | 🟢 Good |
| Access control | User ownership check | 🟢 Good |
| Error handling | Generic messages | 🟡 Fair |
| MFA | Not implemented | 🔴 None |
| Transport | CLI only (N/A) | 🟢 Secure |

**Overall: 🟢 SECURE for educational purposes**

**Để production-ready, cần:**
- ✅ Input validation + sanitization
- ✅ MFA
- ✅ Secure server deployment (HTTPS, etc)
- ✅ Audit logging
- ✅ Regular security testing (penetration testing)

---

**References:**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [RFC 2898 - PBKDF2](https://tools.ietf.org/html/rfc2898)
- [FIPS 197 - AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

---

**Made for security-conscious developers 🔐**
