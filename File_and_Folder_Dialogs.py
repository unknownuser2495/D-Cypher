#Importing necessary modules
from customtkinter import filedialog
from ctypes import windll
windll.shcore.SetProcessDpiAwareness(1)                         # Enable high DPI awareness for UI elements

###########################################################################################
def Select_Folder(title, name_of_file):
    Folder_path = filedialog.askdirectory(title = title)
    
    #Checking if any folder is selected or not
    if Folder_path == "":
        print(f"No folder selected for {name_of_file}")
        exit()

    else:
        return Folder_path
    
    
###########################################################################################
def Select_File(initialdir, title, name_of_file, filetypes):
    File_path = filedialog.askopenfilename(initialdir = initialdir,
                                            title = title,
                                            filetypes = filetypes)
    
    #Checking if any file is selected or not
    if File_path == "":
        print(f"No file selected for {name_of_file}")
        exit()
        
    else:
        return File_path