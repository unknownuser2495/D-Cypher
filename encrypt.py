from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import getpass
import pickle

# Generate AES key using PBKDF2 wit
def generate_aes_key(password, salt):
    # Initialize PBKDF2 with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES key length
        salt=salt,
        iterations=100000,  # Number of iterations
        backend=default_backend()
    )
    
    # Derive AES key from the password
    aes_key = kdf.derive(password.encode())
    return aes_key

# Encrypt a file using AES
def encrypt_file(file_path, output_file_path):
    try:
        # Read plaintext from file
        with open(file_path, 'rb') as file:
            plaintext = file.read()
    except FileNotFoundError:
        print("File not found:", file_path)
        return

    # Generate random salt and initialization vector (IV)
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    password = getpass.getpass("Enter password: ", stream=None)
    
    aes_key = generate_aes_key(password, salt)

    # Initialize AES cipher in CFB mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Encrypt plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Store encrypted data along with salt and IV
    encrypted_data = {
        "salt": salt,
        "iv": iv,
        "cipher": ciphertext
    }

    # Write encrypted data to output file
    with open(output_file_path, 'wb') as output_file:
        pickle.dump(encrypted_data, output_file)
    print("File encrypted successfully!")

# Decrypt a file encrypted with AES
def decrypt_file(encrypted_file_path, output_file_path):
    try:
        # Load encrypted data from file
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = pickle.load(file)
    except FileNotFoundError:
        print("File not found:", encrypted_file_path)
        return

    # Extract salt, IV, and ciphertext from encrypted data
    salt = encrypted_data["salt"]
    iv = encrypted_data["iv"]
    ciphertext = encrypted_data["cipher"]

    # Get password from user input
    password = getpass.getpass("Enter password: ", stream=None)
    # Generate AES key using the same salt
    aes_key = generate_aes_key(password, salt)

    # Initialize AES cipher in CFB mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypt ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write decrypted plaintext to output file
    with open(output_file_path, 'wb') as output_file:
        output_file.write(plaintext)
    print("File decrypted successfully!")

# Main function to provide user interface
def main():
    while True:
       
        print("\nMain Menu:")
        print("1. Encrypt file with AES")
        print("2. Decrypt file with AES")
        print("3. Exit")

        
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            # Encrypt file
            file_to_encrypt = input("Enter the path of the file to encrypt: ")
            if not os.path.exists(file_to_encrypt):
                print("File not found:", file_to_encrypt, " try again.")
            else:
                output_encrypted_file = input("Enter the path for the encrypted file: ")
                encrypt_file(file_to_encrypt, output_encrypted_file)
                
        elif choice == '2':
            # Decrypt file
            encrypted_file = input("Enter the path of the file to decrypt: ")
            if not os.path.exists(encrypted_file):
                print("File not found:", encrypted_file)
            else:
                output_decrypted_file = input("Enter the path for the decrypted file: ")
                decrypt_file(encrypted_file, output_decrypted_file)
                
        elif choice == '3':
            # Exit program
            print("Exiting...")
            break
        else:
            # Invalid choice
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
