"""
FILE ENCRYPTION PROGRAM
This program encrypts files using symmetric encryption
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key_from_password(password, salt):
    """
    Generate encryption key from user password
    Uses PBKDF2 algorithm with SHA256 for security
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def main():
    print("\n" + "="*60)
    print("           FILE ENCRYPTION PROGRAM")
    print("="*60 + "\n")
    
    # STEP 1: Read encryption key from user
    print("STEP 1: Enter Encryption Password")
    print("-" * 60)
    password = input("Enter your encryption password: ")
    
    if len(password) < 6:
        print("ERROR: Password must be at least 6 characters!")
        return
    
    confirm_password = input("Confirm your password: ")
    
    if password != confirm_password:
        print("ERROR: Passwords do not match!")
        return
    
    # Generate salt and encryption key
    salt = os.urandom(16)  # Generate random salt
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    
    print("✓ Encryption key generated successfully!\n")
    
    # STEP 2: List directory files
    print("STEP 2: Scanning Directory Files")
    print("-" * 60)
    
    current_directory = os.getcwd()
    print(f"Current Directory: {current_directory}\n")
    
    files_list = []
    
    for item in os.listdir(current_directory):
        # Skip directories, this script, and already encrypted files
        if os.path.isfile(item) and item != __file__ and not item.endswith('.encrypted'):
            files_list.append(item)
    
    if len(files_list) == 0:
        print("No files found to encrypt!")
        return
    
    print(f"Found {len(files_list)} file(s) to encrypt:\n")
    for idx, filename in enumerate(files_list, 1):
        file_size = os.path.getsize(filename)
        print(f"  {idx}. {filename} ({file_size} bytes)")
    
    print("\n" + "-" * 60)
    confirmation = input("Do you want to encrypt these files? (yes/no): ")
    
    if confirmation.lower() != 'yes':
        print("Encryption cancelled.")
        return
    
    # STEP 3: Encrypt the files
    print("\nSTEP 3: Encrypting Files")
    print("-" * 60)
    
    encrypted_count = 0
    
    for filename in files_list:
        try:
            # Read original file
            with open(filename, 'rb') as file:
                original_data = file.read()
            
            # Encrypt the data
            encrypted_data = cipher.encrypt(original_data)
            
            # Write encrypted file
            encrypted_filename = filename + '.encrypted'
            with open(encrypted_filename, 'wb') as file:
                file.write(encrypted_data)
            
            print(f"✓ Encrypted: {filename} → {encrypted_filename}")
            encrypted_count += 1
            
        except Exception as error:
            print(f"✗ Failed to encrypt {filename}: {error}")
    
    # Save the salt to a file (needed for decryption)
    with open('encryption.salt', 'wb') as salt_file:
        salt_file.write(salt)
    
    print(f"\n✓ Salt saved to 'encryption.salt'")
    
    # STEP 4: Delete old files (OPTIONAL - commented for safety)
    print("\nSTEP 4: Cleanup (Optional)")
    print("-" * 60)
    print("Original files are kept for safety during testing.")
    print("Uncomment deletion code in production environment.\n")
    
    # Uncomment below to delete original files:
    # for filename in files_list:
    #     try:
    #         os.remove(filename)
    #         print(f"✓ Deleted: {filename}")
    #     except Exception as e:
    #         print(f"✗ Error deleting {filename}: {e}")
    
    # Summary
    print("\n" + "="*60)
    print(f"ENCRYPTION COMPLETE!")
    print(f"  • Files encrypted: {encrypted_count}")
    print(f"  • Salt file: encryption.salt")
    print(f"  • Keep your password and salt file safe!")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
    except Exception as e:
        print(f"\nERROR: {e}")