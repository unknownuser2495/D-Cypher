import os
import base64
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


###########################################################################################
def Derive_Key(password, salt):
    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=480000,

    )

    key_1 = base64.urlsafe_b64encode(kdf.derive(password))

    key = Fernet(key_1)
    
    return key


###########################################################################################
def Read_Salt(file_path, generate_salt = True):
    if os.path.exists(file_path):
        file_object = open(r"{}".format(file_path), "rb")
        salt = file_object.read()
        file_object.close()
        return salt
    
    elif generate_salt:
        file_object = open(r"{}".format(file_path),"wb")       #Creating the file for storing key
        salt =  os.urandom(32)                                              #Generating a Salt
        file_object.write(salt)                                              #Writing the salt in the file
        file_object.close()
        return salt
    
    else:
        print("No file found containing the salt")