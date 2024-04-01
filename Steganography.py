#Importing all the modules
import cryptography
from File_and_Folder_Dialogs import Select_Folder, Select_File
from Encryption_Decryption import Derive_Key, Read_Salt
from getpass import getpass

def stego_embed():

    #Opening the files

    masking_file = Select_File(initialdir = "/",
                                            title = "Select the file that you want to mask into",name_of_file = "masking",
                                            filetypes = (("jpg files",
                                                        "*.jpg*"),
                                                       ("jpeg files",
                                                        "*.jpeg*"),("png files", ".png*"),))
    
    secret_content = Select_File(initialdir = "/",
                                            title = "Select the file that you want to hide",name_of_file = "secret content",
                                            filetypes = (("jpg files", ".jpg"),("All Files", "*.*")))

    #Selecting the folder for key
    key_file = Select_Folder(title = "Select the folder where the \"key.key\" file is located or you want to create", name_of_file = "key")

    key_file += r"\key.key"

    #Extracting name of file to hide

    name_of_encoded_file = (chr(0)+((secret_content).split('/'))[-1]).encode('utf-8')

    password = getpass("Enter your passwod. It will be required to decrypt the file. \n").encode('utf-8')

    #Reading the Salt
    salt = Read_Salt(key_file, generate_salt = True)

    #Generating a key
    key = Derive_Key(password, salt)

    #Opening the files

    f1 = open(r"{}".format(masking_file),"ab+")
    f2 = open(r"{}".format(secret_content),"rb")

    content_to_encode = f2.read()+name_of_encoded_file

    #Encrypting the content of the file to be hided
    content_to_write = key.encrypt(content_to_encode)

    #Writing the content
    f1.write(content_to_write)

    #Closing all files
    f1.close()
    f2.close()

    print("File masked successfully")


def stego_extract():

    key_file = Select_Folder(title = "Select the folder where the \"key.key\" file is located or you want to create", name_of_file = "key")

    key_file += r"\key.key" 

    salt = Read_Salt(key_file, generate_salt = True)

    masking_file = Select_File(initialdir = "/",
                                            title = "Select the file that you want to extract data from", name_of_file = "masking",
                                             filetypes = (("jpg files",
                                                        "*.jpg*"),
                                                       ("jpeg files",
                                                        "*.jpeg*"),("png files", ".png*")))
    
    
    f1 = open(r"{}".format(masking_file),"rb")

    #Reading all the contents
    content_in_image = f1.read()

    #Extracting the extension of the file in which data is hidden
    extension_of_masking_file = (((masking_file).split('/'))[-1])[-4 : ]

    #Assigning end of file according to the extension of the file
    EOF =  b'\xFF\xD9' if (extension_of_masking_file in (".jpg",".jpeg")) else b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82'

    #Content of original image
    content_of_original_image = ((content_in_image.split(EOF))[0])+EOF

    #Changing the file pointer's position to right after the content of first image
    offset = content_in_image.index(EOF)
    f1.seek(offset+len(EOF))

    #Reading the encoded content
    encoded_content = f1.read()

    #Checking if there is any content to extract or not
    if encoded_content == b'':
        print("No content in the image to decode")
        exit()
        
    #Asking for the folder path for the 
    secret_content = Select_Folder(title = "Select the folder where you want to extract the decoded file", name_of_file = "secret content")

    #Taking password as input from the user
    password = getpass("Enter the password to decrypt the files : ").encode("utf - 8")
    
    #Generating the key
    key = Derive_Key(password, salt)
    try:
        decoded_content = key.decrypt(encoded_content)
    except cryptography.fernet.InvalidToken as e:
        print("Error: Decryption failed. Invalid key or corrupted data.")
        print(f"Exception details: {e}")
        exit()

    #Extracting the name of the encoded file and adding it to the folder path
    secret_content += "\\"+ (decoded_content.split(chr(0).encode('utf-8'))[-1]).decode('utf-8')

    f2 = open(r"{}".format(secret_content),"wb+")

    #Writing the decoded content
    f2.write(decoded_content)

    print("Do you want to keep the steganographic content in the file?")
    ch = int(input("""1. Yes
2. No   \n"""))

    #Removing the Steganographic content from the masking image
    if ch == 1: 
        pass
    
    else:
        f1 = open(r"{}".format(masking_file),"wb")
        f1.write(content_of_original_image)
        f1.close()

    #Closing the file
    f2.close()
    f2.close()

    print("File unmasked successfully")

def menu():
    
    """
  Prompts the user to choose between encryption and decryption.

  Returns:
      int: 1. Embedding content into the image,
          2. Extracting Steganographic content, or None if invalid choice.
          3. Exit
  """
    while True:
        print("""Choose from the following options : 
          1. Embedding content into the image
          2. Extracting Steganographic content
          3. Exit""")
        
        choice = int(input("Enter your choice : "))

        if choice == 1:  
            stego_embed()
    
        elif choice == 2:
            stego_extract()

        elif choice == 3:
            break

        else:
            print("Choose from given options")

if __name__ == "__main__":
    menu()