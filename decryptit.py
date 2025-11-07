"""
FILE DECRYPTION PROGRAM 
This program decrypts files that were encrypted
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key_from_password(password, salt):
    """
    Generate decryption key from user password
    Must use same algorithm as encryption
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
    print("           FILE DECRYPTION PROGRAM")
    print("="*60 + "\n")
    
    # STEP 1: Read decryption key from user
    print("STEP 1: Enter Decryption Password")
    print("-" * 60)
    
    # Check if salt file exists
    salt_filename = 'encryption.salt'
    if not os.path.exists(salt_filename):
        print(f"ERROR: Salt file '{salt_filename}' not found!")
        print("Cannot decrypt without the salt file from encryption.")
        return
    
    # Load the salt
    with open(salt_filename, 'rb') as salt_file:
        salt = salt_file.read()
    
    print("✓ Salt file loaded successfully")
    
    password = input("Enter your decryption password: ")
    
    # Generate decryption key
    try:
        key = generate_key_from_password(password, salt)
        cipher = Fernet(key)
        print("✓ Decryption key generated successfully!\n")
    except Exception as error:
        print(f"ERROR: Failed to generate key: {error}")
        return
    
    # STEP 2: List encrypted files in directory
    print("STEP 2: Scanning for Encrypted Files")
    print("-" * 60)
    
    current_directory = os.getcwd()
    print(f"Current Directory: {current_directory}\n")
    
    encrypted_files = []
    
    for item in os.listdir(current_directory):
        # Find all .encrypted files
        if os.path.isfile(item) and item.endswith('.encrypted'):
            encrypted_files.append(item)
    
    if len(encrypted_files) == 0:
        print("No encrypted files found!")
        return
    
    print(f"Found {len(encrypted_files)} encrypted file(s):\n")
    for idx, filename in enumerate(encrypted_files, 1):
        file_size = os.path.getsize(filename)
        print(f"  {idx}. {filename} ({file_size} bytes)")
    
    print("\n" + "-" * 60)
    confirmation = input("Do you want to decrypt these files? (yes/no): ")
    
    if confirmation.lower() != 'yes':
        print("Decryption cancelled.")
        return
    
    # STEP 3: Decrypt the files
    print("\nSTEP 3: Decrypting Files")
    print("-" * 60)
    
    decrypted_count = 0
    failed_count = 0
    
    for encrypted_filename in encrypted_files:
        try:
            # Read encrypted file
            with open(encrypted_filename, 'rb') as file:
                encrypted_data = file.read()
            
            # Decrypt the data
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Get original filename (remove .encrypted extension)
            original_filename = encrypted_filename.replace('.encrypted', '')
            
            # Write decrypted file
            with open(original_filename, 'wb') as file:
                file.write(decrypted_data)
            
            print(f"✓ Decrypted: {encrypted_filename} → {original_filename}")
            decrypted_count += 1
            
        except Exception as error:
            print(f"✗ Failed to decrypt {encrypted_filename}")
            print(f"  Error: {error}")
            print(f"  (Wrong password or corrupted file)")
            failed_count += 1
    
    # STEP 4: Delete encrypted files (OPTIONAL - commented for safety)
    print("\nSTEP 4: Cleanup (Optional)")
    print("-" * 60)
    print("Encrypted files are kept for safety during testing.")
    print("Uncomment deletion code in production environment.\n")
    
    # Uncomment below to delete encrypted files:
    # for filename in encrypted_files:
    #     try:
    #         os.remove(filename)
    #         print(f"✓ Deleted: {filename}")
    #     except Exception as e:
    #         print(f"✗ Error deleting {filename}: {e}")
    # 
    # # Delete salt file
    # try:
    #     os.remove(salt_filename)
    #     print(f"✓ Deleted: {salt_filename}")
    # except Exception as e:
    #     print(f"✗ Error deleting {salt_filename}: {e}")
    
    # Summary
    print("\n" + "="*60)
    print(f"DECRYPTION COMPLETE!")
    print(f"  • Files successfully decrypted: {decrypted_count}")
    if failed_count > 0:
        print(f"  • Files failed: {failed_count}")
    print(f"  • Your files have been restored!")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
    except Exception as e:
        print(f"\nERROR: {e}")