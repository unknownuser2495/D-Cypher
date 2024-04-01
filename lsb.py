import os
import argparse
import secrets
import sys
import cv2
import numpy as np
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hidden

# Constants
KEYS_DIR = 'keys'
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'mypublickey.pem')
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'myprivatekey.pem')
SECRET_INFO_PATH = 'secret_info.bin'

# Encryption parameters
ITERATIONS = 100000
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16

def generate_keys():
    try:
        if not os.path.exists(KEYS_DIR):
            os.makedirs(KEYS_DIR)
        elif os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
            print("Keys already exist.")
            return

        # Generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Ask the user for a passphrase to encrypt the private key
        password = getpass("Enter passphrase for private key: ").encode('utf-8')

        # Define the encryption algorithm.
        encryption_algorithm = serialization.BestAvailableEncryption(password)

        # Serialize the private key with the specified encryption algorithm
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        # Write the encrypted private key to a file
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(pem_private)

        print("Private key generated and saved successfully.")

        # Generate the public key
        public_key = private_key.public_key()

        # Serialize the public key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Write the public key to a file
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pem_public)

        print("Public key generated and saved successfully.")
    except Exception as e:
        print(f"Error generating keys: {e}")
        
def load_key(key_path, passphrase=None):
    with open(key_path, 'rb') as key_file:
        if passphrase:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=passphrase.encode(),
                backend=default_backend()
            )
            return private_key
        else:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            return public_key

def generate_salt():
    return secrets.token_bytes(SALT_LENGTH)

def derive_key(session_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(session_key)


def encrypt_text(plaintext, public_key):
    try:
        session_key = secrets.token_bytes(KEY_LENGTH)
        salt = generate_salt()

        enc_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        symmetric_key = derive_key(session_key, salt)
        iv = secrets.token_bytes(IV_LENGTH)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return enc_session_key, salt, iv, ciphertext
    except Exception as e:
        print(f"Error encrypting text: {e}")
        return None, None, None, None

def encode_text_into_image_menu():
    try:
        # Check if the private key file exists
        if not os.path.exists(PRIVATE_KEY_PATH):
            print("Error: Private key file not found. Please generate keys first.")
            return
        
        # Load public key with error handling
        public_key = load_key(PUBLIC_KEY_PATH)
        if public_key is None:
            print("Error: Public key not found. Please generate keys first.")
            return

        input_image_location = input("Enter location of the original image: ")
        
        # Check if the input image exists
        if not os.path.exists(input_image_location):
            print("Error: Input image not found.")
            return

        output_image_name = input("Enter the name for the output image (including extension): ")
        
        # Ask user for text to encrypt
        plaintext = input("Enter the text to encrypt: ")

        # Encrypt the text
        enc_session_key, salt, iv, ciphertext = encrypt_text(plaintext, public_key)
        if enc_session_key is None:
            return

        # Encode data into the image
        encoded_image = hidden.encode_data(input_image_location, ciphertext)
        output_image_path = os.path.join(os.path.dirname(input_image_location), output_image_name)
        cv2.imwrite(output_image_path, encoded_image)
        print("Data successfully encoded into the image and saved as", output_image_name)
        print("Ciphered text is:", ciphertext)
        save_secret_info(enc_session_key, salt, iv, len(ciphertext), filename="secret_info.bin")
    except Exception as e:
        print(f"Error encoding text into image: {e}")

def decode_text_from_image_menu():
    try:
        # Check if the private key file exists
        if not os.path.exists(PRIVATE_KEY_PATH):
            print("Error: Private key file not found. Please generate keys first.")
            return

        # Load private key with error handling
        passphrase = getpass("Enter passphrase for the private key: ")
        private_key = load_key(PRIVATE_KEY_PATH, passphrase)
        if private_key is None:
            return
            
        # Load secret info with error handling
        enc_session_key, salt, iv, cipherlen = load_secret_info(SECRET_INFO_PATH)
        if enc_session_key is None or salt is None or iv is None or cipherlen is None:
            print("Secret info file is corrupt or incomplete. Please encode text into the image first.")
            return

        encoded_image_location = input("Enter location of the encoded image: ")
        if not os.path.exists(encoded_image_location):
            print("Error: Encoded image not found.")
            return

        # Decrypt the encrypted session key
        dec_session_key = private_key.decrypt(
            enc_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Re-derive the symmetric key
        symmetric_key = derive_key(dec_session_key, salt)

        # Decode data from the image
        decoded_data = hidden.decode_data(encoded_image_location, cipherlen)

        # Decrypt the data
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(decoded_data) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        print("Decrypted text:", plaintext.decode())
    except Exception as e:
        print(f"Error decoding text from image: {e}")

def save_secret_info(enc_session_key, salt, iv, cipherlen, filename="secret_info.bin"):
    with open(filename, 'wb') as f:
        f.write(enc_session_key)
        f.write(salt)
        f.write(iv)
        f.write(cipherlen.to_bytes(4, byteorder='big'))  # Save ciphertext length as 4-byte integer

def load_secret_info(filename="secret_info.bin"):
    with open(filename, 'rb') as f:
        enc_session_key = f.read(512)  # Assuming encrypted session key is 512 bytes
        salt = f.read(SALT_LENGTH)
        iv = f.read(IV_LENGTH)
        cipherlen = f.read(4)  # Read 4 bytes for ciphertext length
        cipherlen = int.from_bytes(cipherlen, byteorder='big')
    return enc_session_key, salt, iv, cipherlen
    
def menu():
    while True:
        print("\n--- Main Menu ---")
        print("1. Generate Keys")
        print("2. Encode Text into Image")
        print("3. Decode Text from Image")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            generate_keys()
        elif choice == "2":
            encode_text_into_image_menu()
        elif choice == "3":
            decode_text_from_image_menu()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 4.")

if __name__ == "__main__":
    menu()
