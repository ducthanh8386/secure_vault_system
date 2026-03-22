"""
======================================
MODULE: config.py
Cấu hình chung cho Secure Vault System
======================================
"""

# ============= DATABASE =============
DATABASE_PATH = "vault.db"
ENCRYPTED_FILES_FOLDER = "./encrypted_files"

# ============= SECURITY =============

# PBKDF2 Configuration
PBKDF2_ITERATIONS = 100000  # 100,000 iterations (chuẩn NIST)
PBKDF2_ALGORITHM = "sha256"
PBKDF2_OUTPUT_LENGTH = 32  # 256-bit for AES-256

# AES Configuration
AES_KEY_LENGTH = 32  # 256-bit
AES_IV_LENGTH = 16  # 128-bit (standard for AES)
AES_ALGORITHM = "AES-256-CBC"

# Hashing Configuration
HASH_ALGORITHM = "sha256"
HASH_SALT_LENGTH = 16  # 128-bit salt

# ============= VALIDATION =============

# Username
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50

# Password
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 128

# ============= FILE UPLOAD =============

# Maximum file size (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Allowed file extensions (empty = allow all)
# ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.png'}
ALLOWED_EXTENSIONS = []  # Allow all

# ============= UI =============

# CLI Colors (optional)
COLORS_ENABLED = True

# ============= LOGGING =============

# Enable logging
LOGGING_ENABLED = True
LOG_FILE = "vault.log"

# ============= SESSION =============

# Session timeout (seconds) - 0 = never timeout
SESSION_TIMEOUT = 0

# ============= PERFORMANCE =============

# Chunk size for large file processing (1 MB)
FILE_CHUNK_SIZE = 1024 * 1024

# ============= FEATURE FLAGS =============

# Enable password strength checker
FEATURE_PASSWORD_STRENGTH_CHECK = True

# Enable file integrity checking
FEATURE_FILE_INTEGRITY_CHECK = True

# Enable auto-logout
FEATURE_AUTO_LOGOUT = False

# ============= DEBUG =============

DEBUG = False
VERBOSE = False


def get_config():
    """
    Lấy toàn bộ cấu hình
    
    Returns:
        dict: Cấu hình hiện tại
    """
    return {
        "database": {
            "path": DATABASE_PATH,
            "encrypted_files_folder": ENCRYPTED_FILES_FOLDER
        },
        "security": {
            "pbkdf2": {
                "iterations": PBKDF2_ITERATIONS,
                "algorithm": PBKDF2_ALGORITHM,
                "output_length": PBKDF2_OUTPUT_LENGTH
            },
            "aes": {
                "key_length": AES_KEY_LENGTH,
                "iv_length": AES_IV_LENGTH,
                "algorithm": AES_ALGORITHM
            },
            "hash": {
                "algorithm": HASH_ALGORITHM,
                "salt_length": HASH_SALT_LENGTH
            }
        },
        "validation": {
            "username_length": (MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH),
            "password_length": (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
        }
    }


if __name__ == "__main__":
    # Print config
    import json
    config = get_config()
    print(json.dumps(config, indent=2))
