"""
File Encryptor Module
Provides file encryption and decryption capabilities using AES encryption.
"""

import os
import hashlib
import base64
import getpass
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class FileEncryptor:
    """File encryption and decryption functionality for the cybersecurity toolkit."""
    
    def __init__(self):
        """Initialize the file encryptor."""
        self.key = None
        self.encrypted_files = []
        self.key_file = "encryption_key.key"
    
    def display_menu(self):
        """Display file encryption menu options."""
        print("\n" + "-"*40)
        print("FILE ENCRYPTION OPTIONS")
        print("-"*40)
        print("1. Generate New Encryption Key")
        print("2. Load Existing Key")
        print("3. Encrypt File")
        print("4. Decrypt File")
        print("5. Encrypt Directory")
        print("6. Decrypt Directory")
        print("7. Secure File Deletion")
        print("8. Key Management")
        print("9. View Encrypted Files")
        print("10. Back to Main Menu")
        print("-"*40)
    
    def get_user_choice(self):
        """Get user's menu choice with validation."""
        while True:
            try:
                choice = input("\nEnter your choice (1-10): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']:
                    return int(choice)
                else:
                    print("Invalid choice. Please enter a number between 1-10.")
            except KeyboardInterrupt:
                return 10
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def generate_key(self):
        """Generate a new encryption key."""
        print("\n--- GENERATE NEW ENCRYPTION KEY ---")
        
        try:
            # Generate a new key
            self.key = Fernet.generate_key()
            
            # Save key to file
            with open(self.key_file, 'wb') as key_file:
                key_file.write(self.key)
            
            print(f"New encryption key generated and saved to {self.key_file}")
            print("IMPORTANT: Keep this key file safe! You cannot decrypt files without it.")
            
            # Ask if user wants to set a password for the key
            password_protect = input("Do you want to password-protect this key? (y/n): ").strip().lower()
            if password_protect == 'y':
                self.password_protect_key()
                
        except Exception as e:
            print(f"Error generating key: {e}")
    
    def password_protect_key(self):
        """Add password protection to the encryption key."""
        print("\n--- PASSWORD PROTECT KEY ---")
        
        try:
            password = getpass.getpass("Enter password for key protection: ")
            if not password:
                print("Error: Password cannot be empty.")
                return
            
            # Derive key from password
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Save password-protected key
            protected_key_file = f"{self.key_file}.protected"
            with open(protected_key_file, 'wb') as f:
                f.write(salt + key)
            
            print(f"Key protected with password and saved to {protected_key_file}")
            
        except Exception as e:
            print(f"Error protecting key: {e}")
    
    def load_key(self):
        """Load an existing encryption key."""
        print("\n--- LOAD EXISTING KEY ---")
        
        key_path = input("Enter path to key file: ").strip()
        if not key_path:
            print("Error: Key path cannot be empty.")
            return
        
        if not os.path.exists(key_path):
            print(f"Error: Key file '{key_path}' not found.")
            return
        
        try:
            with open(key_path, 'rb') as key_file:
                self.key = key_file.read()
            
            print(f"Key loaded successfully from {key_path}")
            
        except Exception as e:
            print(f"Error loading key: {e}")
    
    def encrypt_file(self):
        """Encrypt a single file."""
        print("\n--- ENCRYPT FILE ---")
        
        if not self.key:
            print("Error: No encryption key loaded. Please generate or load a key first.")
            return
        
        file_path = input("Enter path to file to encrypt: ").strip()
        if not file_path:
            print("Error: File path cannot be empty.")
            return
        
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return
        
        try:
            # Read file content
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            # Encrypt the data
            fernet = Fernet(self.key)
            encrypted_data = fernet.encrypt(file_data)
            
            # Save encrypted file
            encrypted_path = f"{file_path}.encrypted"
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            print(f"File encrypted successfully: {encrypted_path}")
            
            # Record encrypted file
            self.encrypted_files.append({
                'original_path': file_path,
                'encrypted_path': encrypted_path,
                'encrypted_at': self.get_current_timestamp()
            })
            
            # Ask if user wants to delete original file
            delete_original = input("Delete original file? (y/n): ").strip().lower()
            if delete_original == 'y':
                self.secure_delete_file(file_path)
                print("Original file securely deleted.")
            
        except Exception as e:
            print(f"Error encrypting file: {e}")
    
    def decrypt_file(self):
        """Decrypt a single file."""
        print("\n--- DECRYPT FILE ---")
        
        if not self.key:
            print("Error: No encryption key loaded. Please generate or load a key first.")
            return
        
        encrypted_path = input("Enter path to encrypted file: ").strip()
        if not encrypted_path:
            print("Error: File path cannot be empty.")
            return
        
        if not os.path.exists(encrypted_path):
            print(f"Error: File '{encrypted_path}' not found.")
            return
        
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            # Decrypt the data
            fernet = Fernet(self.key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Determine output path
            if encrypted_path.endswith('.encrypted'):
                output_path = encrypted_path[:-10]  # Remove .encrypted extension
            else:
                output_path = input("Enter output path for decrypted file: ").strip()
                if not output_path:
                    print("Error: Output path cannot be empty.")
                    return
            
            # Save decrypted file
            with open(output_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            print(f"File decrypted successfully: {output_path}")
            
        except Exception as e:
            print(f"Error decrypting file: {e}")
    
    def encrypt_directory(self):
        """Encrypt all files in a directory."""
        print("\n--- ENCRYPT DIRECTORY ---")
        
        if not self.key:
            print("Error: No encryption key loaded. Please generate or load a key first.")
            return
        
        dir_path = input("Enter path to directory to encrypt: ").strip()
        if not dir_path:
            print("Error: Directory path cannot be empty.")
            return
        
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            print(f"Error: Directory '{dir_path}' not found or not a directory.")
            return
        
        try:
            encrypted_count = 0
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if not file_path.endswith('.encrypted'):  # Skip already encrypted files
                        print(f"Encrypting: {file_path}")
                        self.encrypt_single_file(file_path)
                        encrypted_count += 1
            
            print(f"Directory encryption completed. {encrypted_count} files encrypted.")
            
        except Exception as e:
            print(f"Error encrypting directory: {e}")
    
    def encrypt_single_file(self, file_path: str):
        """Helper method to encrypt a single file."""
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            fernet = Fernet(self.key)
            encrypted_data = fernet.encrypt(file_data)
            
            encrypted_path = f"{file_path}.encrypted"
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            self.encrypted_files.append({
                'original_path': file_path,
                'encrypted_path': encrypted_path,
                'encrypted_at': self.get_current_timestamp()
            })
            
        except Exception as e:
            print(f"Error encrypting {file_path}: {e}")
    
    def decrypt_directory(self):
        """Decrypt all encrypted files in a directory."""
        print("\n--- DECRYPT DIRECTORY ---")
        
        if not self.key:
            print("Error: No encryption key loaded. Please generate or load a key first.")
            return
        
        dir_path = input("Enter path to directory to decrypt: ").strip()
        if not dir_path:
            print("Error: Directory path cannot be empty.")
            return
        
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            print(f"Error: Directory '{dir_path}' not found or not a directory.")
            return
        
        try:
            decrypted_count = 0
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.endswith('.encrypted'):
                        encrypted_path = os.path.join(root, file)
                        print(f"Decrypting: {encrypted_path}")
                        self.decrypt_single_file(encrypted_path)
                        decrypted_count += 1
            
            print(f"Directory decryption completed. {decrypted_count} files decrypted.")
            
        except Exception as e:
            print(f"Error decrypting directory: {e}")
    
    def decrypt_single_file(self, encrypted_path: str):
        """Helper method to decrypt a single file."""
        try:
            with open(encrypted_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            fernet = Fernet(self.key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            output_path = encrypted_path[:-10]  # Remove .encrypted extension
            with open(output_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
        except Exception as e:
            print(f"Error decrypting {encrypted_path}: {e}")
    
    def secure_delete_file(self, file_path: str):
        """Securely delete a file by overwriting it multiple times."""
        print("\n--- SECURE FILE DELETION ---")
        
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return
        
        try:
            file_size = os.path.getsize(file_path)
            
            # Overwrite file multiple times with random data
            with open(file_path, 'r+b') as file:
                for _ in range(3):  # Overwrite 3 times
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            
            # Delete the file
            os.remove(file_path)
            print(f"File '{file_path}' securely deleted.")
            
        except Exception as e:
            print(f"Error securely deleting file: {e}")
    
    def key_management(self):
        """Manage encryption keys."""
        print("\n--- KEY MANAGEMENT ---")
        print("Key management functionality - PLACEHOLDER")
        print("To implement:")
        print("1. List all available keys")
        print("2. Backup keys to secure location")
        print("3. Restore keys from backup")
        print("4. Change key passwords")
        print("5. Delete old keys")
        print("6. Key rotation")
        
        if self.key:
            print(f"\nCurrent key loaded: {self.key_file}")
            print("Key fingerprint:", hashlib.sha256(self.key).hexdigest()[:16])
        else:
            print("No key currently loaded.")
    
    def view_encrypted_files(self):
        """View list of encrypted files."""
        print("\n--- ENCRYPTED FILES ---")
        
        if not self.encrypted_files:
            print("No encrypted files recorded.")
            return
        
        print(f"Found {len(self.encrypted_files)} encrypted files:")
        for i, file_info in enumerate(self.encrypted_files, 1):
            print(f"  {i}. {file_info['original_path']}")
            print(f"     Encrypted: {file_info['encrypted_path']}")
            print(f"     Date: {file_info['encrypted_at']}")
            print()
    
    def get_current_timestamp(self) -> str:
        """Get current timestamp as string."""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def run(self):
        """Main file encryption interface."""
        while True:
            try:
                self.display_menu()
                choice = self.get_user_choice()
                
                if choice == 1:
                    self.generate_key()
                elif choice == 2:
                    self.load_key()
                elif choice == 3:
                    self.encrypt_file()
                elif choice == 4:
                    self.decrypt_file()
                elif choice == 5:
                    self.encrypt_directory()
                elif choice == 6:
                    self.decrypt_directory()
                elif choice == 7:
                    file_path = input("Enter file path to securely delete: ").strip()
                    if file_path:
                        self.secure_delete_file(file_path)
                elif choice == 8:
                    self.key_management()
                elif choice == 9:
                    self.view_encrypted_files()
                elif choice == 10:
                    break
                
                if choice != 10:
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nReturning to main menu...")
                break
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                input("Press Enter to continue...")


# Example usage and testing
if __name__ == "__main__":
    encryptor = FileEncryptor()
    encryptor.run()
