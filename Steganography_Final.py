#Importing all the modules

import os
import base64
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from customtkinter import filedialog
from ctypes import windll
windll.shcore.SetProcessDpiAwareness(1)                         # Enable high DPI awareness for UI elements



def stego_embed():

    #Opening the files

    name_of_file_1 = filedialog.askopenfilename(initialdir = "/",
                                            title = "Select the file that you want to mask into",
                                            filetypes = (("jpg files",
                                                        "*.jpg*"),
                                                       ("jpeg files",
                                                        "*.jpeg*"),("png files", ".png*"),))
    
    name_of_file_2 = filedialog.askopenfilename(initialdir = "/",
                                            title = "Select the file that you want to hide",
                                            filetypes = (("jpg files", ".jpg"),("All Files", "*.*")))
    
    #Selecting the folder for key

    name_of_file_k = filedialog.askdirectory(title = "Select the folder where the \"key.key\" file is located or you want to create")

    name_of_file_k += r"\key.key"

    #extracting name of file to hide

    name_of_encoded_file = (chr(0)+((name_of_file_2).split('/'))[-1]).encode('utf-8')

    password = (input("Enter your passwod. It will be required to decrypt the file. \n")).encode('utf-8')

    if (name_of_encoded_file == "" or name_of_file_2 == ""):
        print("Please select a file")
        exit()

    #Checking if key files exists or not
    try :
        k_f = open(r"{}".format(name_of_file_k),"rb")
        salt = k_f.read()       #Reading the salt from the file

    except FileNotFoundError:
        k_f = open(r"{}".format(name_of_file_k),"wb")       #Creating the file for storing key
        salt =  os.urandom(32)                                              #Generating a Salt
        k_f.write(salt)                                                         #Writing the salt in the file


    #Generating a key
    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=480000,

    )

    key_1 = base64.urlsafe_b64encode(kdf.derive(password))

    key = Fernet(key_1)

    #Opening the files

    f1 = open(r"{}".format(name_of_file_1),"ab+")
    f2 = open(r"{}".format(name_of_file_2),"rb+")

    content_to_encode = f2.read()+name_of_encoded_file

    #Encrypting the content of the file to be hided
    content_to_write = key.encrypt(content_to_encode)

    #Writing the content
    f1.write(content_to_write)

    #Closing all files
    f1.close()
    f2.close()
    k_f.close()

    print("File masked successfully")



def stego_extract():

    password = (input("Enter the password to decrypt the files : ")).encode("utf - 8")

    name_of_file_k = filedialog.askdirectory(title = "Select the folder where the \"key.key\" file is located or you want to create")
    name_of_file_k += r"\key.key" 

    try :
        k_f = open(r"{}".format(name_of_file_k),"rb")
        salt = k_f.read()

    except FileNotFoundError:
        print("No file has been encrypted yet")

    name_of_file_1 = filedialog.askopenfilename(initialdir = "/",
                                            title = "Select the file that you want to extract data from",
                                             filetypes = (("jpg files",
                                                        "*.jpg*"),
                                                       ("jpeg files",
                                                        "*.jpeg*"),("png files", ".png*")))
    
    if (name_of_file_1 == ""):
        print("Please select a file with steganographic content")
        exit()
    
    name_of_file_2 = filedialog.askdirectory(title = "Select the folder where you want to extract the decoded file")

    if(name_of_file_2 == ""):
        print("Please select a folder for the decrypted file")
        exit()

    f1 = open(r"{}".format(name_of_file_1),"rb")

    content_in_image = f1.read()

    name_of_file_1_ = chr(0)+((name_of_file_1).split('/'))[-1]

    '''if (name_of_file_1 != ".jpg" or name_of_file_1 != ".png"):
        print("Cannot decode content from this file")
        exit()'''

    EOF =  b'\xFF\xD9' if (name_of_file_1_[-4] ==  ".jpg" or name_of_file_1_ == ".jpeg") else b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82'
    
    '''if (name_of_file_1_[-4] ==  ".jpg"):
        EOF = b'\xFF\xD9'

    elif(name_of_file_1_[-4] ==  ".png"):
        EOF = b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82'
        '''

    content_of_original_image = ((content_in_image.split(EOF))[0])+EOF

    offset = content_in_image.index(EOF)
    f1.seek(offset+len(EOF))
    encoded_content = f1.read()

    try:
        kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=480000,

        )

        key_1 = base64.urlsafe_b64encode(kdf.derive(password))

        key = Fernet(key_1)

        decoded_content = key.decrypt(encoded_content)

    except TypeError or cryptography.fernet.InvalidToken:
        print("""Key didn't match. 
Either you've selected the wrong file for key or the password that you have entered is incorrect.""")
        exit()

    name_of_file_2 += "\\"+ (decoded_content.split(chr(0).encode('utf-8'))[-1]).decode('utf-8')

    f2 = open(r"{}".format(name_of_file_2),"wb+")

    f2.write(decoded_content)

    f1 = open(r"{}".format(name_of_file_1),"wb")
    f1.write(content_of_original_image)

    f1.close()
    f2.close()
    k_f.close()

    print("File unmasked successfully")

if __name__ == "__main__":
    
    """
  Prompts the user to choose between encryption and decryption.

  Returns:
      int: 1 for encryption, 2 for decryption, or None if invalid choice.
  """

    print("""Choose from the following options : 
          1. Encryption
          2. Decryption""")
    choice = int(input("Enter your choice : "))

    if choice == 1:  
        stego_embed()
    
    elif choice == 2:
        stego_extract()

    else:
        print("Choose from given options")