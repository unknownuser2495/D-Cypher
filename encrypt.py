from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
# Function to generate AES key using PBKDF2HMAC
def generate_aes_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, 
        backend=default_backend()
    )
    aes_key = kdf.derive(password.encode())
    return aes_key,salt

def encrypt_file(file_path, aes_key, output_file_path):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = os.urandom(16)  # 16 bytes for AES block size
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file_path, 'wb') as output_file:
        output_file.write(iv + ciphertext)

# Function to decrypt a file using AES
def decrypt_file(encrypted_file_path, aes_key, output_file_path):
    with open(encrypted_file_path, 'rb') as file:
        iv = file.read(16)  # Read the first 16 bytes for IV
        ciphertext = file.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_file_path, 'wb') as output_file:
        output_file.write(plaintext)

def main():
    while True:
        print("\nMain Menu:")
        print("1. Generate AES key")
        print("2. Encrypt file with AES")
        print("3. Decrypt file with AES")
        print("4. Exit")

        choice = int(input("Enter your choice (1-4): "))

        if choice == 1:
            password = input("Enter password: ")
            aes_key = generate_aes_key(password)
            with open("aes_key.bin", "wb") as key_file:
                key_file.write(aes_key)
            print("AES key generated successfully and saved to aes_key.bin")
        elif choice == 2:
            file_to_encrypt = input("Enter the path of the file to encrypt: ")
            output_encrypted_file = input("Enter the path for the encrypted file: ")
            with open("aes_key.bin", "rb") as key_file:
                aes_key = key_file.read()
            encrypt_file(file_to_encrypt, aes_key, output_encrypted_file)
            print("File encrypted successfully!")
        elif choice == 3:
            encrypted_file = input("Enter the path of the file to decrypt: ")
            output_decrypted_file = input("Enter the path for the decrypted file: ")
            aes_key_file = input("Enter the path of the file containing AES key: ")
            with open(aes_key_file, "rb") as key_file:
                aes_key = key_file.read()
            decrypt_file(encrypted_file, aes_key, output_decrypted_file)
            print("File decrypted successfully!")
        elif choice == 4:
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
