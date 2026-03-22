"""
======================================
TEST_ALL.PY
Test tất cả module của Secure Vault System
======================================

Chạy script này để test:
- Encryption (AES-256)
- Hashing (SHA-256 + salt)
- Key Derivation (PBKDF2)
- Database (SQLite)
- Authentication (register/login)
- Password Manager
- File Handler

Command: python test_all.py
"""

import os
import sys
import shutil
from pathlib import Path

# Test modules
def test_encryption():
    """Test AES encryption"""
    print("\n" + "="*60)
    print("1️⃣  TEST ENCRYPTION (AES-256)")
    print("="*60)
    try:
        from encryption import test_encryption as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def test_hashing():
    """Test SHA-256 + salt"""
    print("\n" + "="*60)
    print("2️⃣  TEST HASHING (SHA-256 + Salt)")
    print("="*60)
    try:
        from hashing import test_hashing as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def test_key_derivation():
    """Test PBKDF2"""
    print("\n" + "="*60)
    print("3️⃣  TEST KEY DERIVATION (PBKDF2)")
    print("="*60)
    try:
        from key_derivation import test_key_derivation as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def test_database():
    """Test SQLite Database"""
    print("\n" + "="*60)
    print("4️⃣  TEST DATABASE (SQLite)")
    print("="*60)
    try:
        from database import test_database as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def test_auth():
    """Test Authentication"""
    print("\n" + "="*60)
    print("5️⃣  TEST AUTHENTICATION")
    print("="*60)
    try:
        from auth import test_auth as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def test_password_manager():
    """Test Password Manager"""
    print("\n" + "="*60)
    print("6️⃣  TEST PASSWORD MANAGER")
    print("="*60)
    try:
        from password_manager import test_password_manager as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def test_file_handler():
    """Test File Handler"""
    print("\n" + "="*60)
    print("7️⃣  TEST FILE HANDLER")
    print("="*60)
    try:
        from file_handler import test_file_handler as test_func
        test_func()
        return True
    except Exception as e:
        print(f"[❌] Error: {e}")
        return False

def print_banner():
    """Print banner"""
    print("\n")
    print("="*60)
    print("  🔐 SECURE VAULT SYSTEM - TEST SUITE 🔐")
    print("="*60)
    print()

def print_summary(results):
    """Print test summary"""
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    tests = [
        "Encryption (AES-256)",
        "Hashing (SHA-256 + Salt)",
        "Key Derivation (PBKDF2)",
        "Database (SQLite)",
        "Authentication",
        "Password Manager",
        "File Handler"
    ]
    
    for i, (test_name, result) in enumerate(zip(tests, results)):
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{i+1}. {test_name:<30} {status}")
    
    print("="*60)
    
    total = len(results)
    passed = sum(results)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        return True
    else:
        print(f"\n⚠️ {total - passed} test(s) failed")
        return False

def main():
    """Run all tests"""
    print_banner()
    
    results = []
    
    # Run tests
    results.append(test_encryption())
    results.append(test_hashing())
    results.append(test_key_derivation())
    results.append(test_database())
    results.append(test_auth())
    results.append(test_password_manager())
    results.append(test_file_handler())
    
    # Print summary
    success = print_summary(results)
    
    # Cleanup
    print("\n🧹 Cleaning up test files...")
    test_files = [
        "test_auth.db",
        "test_auth",
        "test_fh.db",
        "test_fh",
        "test_pm.db",
        "test_pm",
        "test_vault.db",
        "test_vault",
        "test_document.txt",
        "test_decrypted.txt"
    ]
    
    for f in test_files:
        if os.path.exists(f):
            if os.path.isdir(f):
                shutil.rmtree(f, ignore_errors=True)
            else:
                os.remove(f)
            print(f"  Removed: {f}")
    
    # Remove test_encrypted folder
    if os.path.exists("test_encrypted"):
        shutil.rmtree("test_encrypted", ignore_errors=True)
        print("  Removed: test_encrypted/")
    
    print("\n✅ Cleanup complete!")
    
    # Exit with status
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
