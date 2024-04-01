import Steganography
import encrypt
import lsb 

while True:
    print("""Choose from the following options:
        1. Steganography
        2. Text Steganography
        3. File Encryption
        4. Exit""")

    choice = int(input("Enter your choice : "))

    if choice == 1:
        Steganography.menu()

    elif choice == 2:
        lsb.menu()

    elif choice == 3:
        encrypt.menu()
    
    elif choice == 4:
        exit()

    else:
        print("Please select from given options")