from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import getpass
import pickle

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, 
        backend=default_backend()
    )
    aes_key = kdf.derive(password.encode())
    return aes_key

def encrypt_file(file_path, output_file_path):
    try:
        with open(file_path, 'rb') as file:
            plaintext = file.read()
    except FileNotFoundError:
        print("File not found:", file_path)
        return

    salt = os.urandom(16)
    iv = os.urandom(16)
    password = getpass.getpass("Enter password: ", stream=None)
    aes_key = generate_aes_key(password, salt)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphyr = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_data = {
        "salt": salt,
        "iv": iv,
        "cipher": ciphyr
    }

    with open(output_file_path, 'wb') as output_file:
        pickle.dump(encrypted_data, output_file)
    print("File encrypted successfully!")

def decrypt_file(encrypted_file_path, output_file_path):
    try:
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = pickle.load(file)
    except FileNotFoundError:
        print("File not found:", encrypted_file_path)
        return

    salt = encrypted_data["salt"]
    iv = encrypted_data["iv"]
    ciphyr = encrypted_data["cipher"]

    password = getpass.getpass("Enter password: ", stream=None)
    aes_key = generate_aes_key(password, salt)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphyr) + decryptor.finalize()

    with open(output_file_path, 'wb') as output_file:
        output_file.write(plaintext)
    print("File decrypted successfully!")

def menu():
    while True:
        print("\nMain Menu:")
        print("1. Encrypt file with AES")
        print("2. Decrypt file with AES")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            file_to_encrypt = input("Enter the path of the file to encrypt: ")
            if not os.path.exists(file_to_encrypt):
                print("File not found:", file_to_encrypt, " try again.")
            else:
                output_encrypted_file = input("Enter the path for the encrypted file: ")
                encrypt_file(file_to_encrypt, output_encrypted_file)
                
        elif choice == '2':
            encrypted_file = input("Enter the path of the file to decrypt: ")
            if not os.path.exists(encrypted_file):
                print("File not found:", encrypted_file)
            else:
                output_decrypted_file = input("Enter the path for the decrypted file: ")
                decrypt_file(encrypted_file, output_decrypted_file)
                
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    menu()
