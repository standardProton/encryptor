
import os, hashlib, base64, cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

def readConfig():
    config = {}
    if (os.path.exists(os.getcwd() + "/encryption.config")):
        with open(os.getcwd() + "/encryption.config") as configfile:
            lines = configfile.readlines()
            for line in lines:
                if (len(line) > 0):
                    line_split = line.split("=")
                    config[line_split[0].lower()] = "" if len(line_split) == 0 else line_split[1].lower().strip()
    else: return None
    return config

def saveConfig(config):
    cstr = ""
    for key, value in config.items(): cstr += key + "=" + value + "\n"
    with open(os.getcwd() + "/encryption.config", 'w') as f:
        f.write(cstr)

def decrypt(text, aes_cfb):
    cipher = aes_cfb.decryptor()
    return cipher.update(bytes.fromhex(text)).decode('latin-1') + cipher.finalize().decode('latin-1')

def isascii(s):
    try:
        s.encode('ascii')
        return True
    except: return False

def protected_directory(dir_path):
    return dir_path.__contains__(".git") or dir_path.__contains__("__pycache__") or dir_path.__contains__(".noenc")

def protected_file(file):
    return file == "decrypt.py" or file == "encrypt.py" or file == "encryption.config" or file == ".gitignore" \
        or file.endswith(".pyc") or file.startswith(".noenc")

class dirElement: #Folder names must be encrypted after files for os.walk to be continuous, so a tree is needed.
    def __init__(self, dir_name, parent_dir):
        self.dir_name = dir_name
        self.parent_dir = parent_dir
        self.items = []

    def printAll(self):
        for i in range(0, len(self.items)):
            self.items[i].printAll()
        print("<root>" if self.dir_name == None else (self.parent_dir + "/" + self.dir_name))

    def getList(self, r=[]): #(parent_dir, dir_name)
        for i in range(0, len(self.items)):
            self.items[i].getList(r)
        if (self.dir_name != None): r.append((self.parent_dir, self.dir_name))
        return r
    
    def addElement(self, namesplit, recursive_parent=""): #Recursively add new element given format 'folder_a/folder_b/folder_c' -> ['folder_a', 'folder_b', 'folder_c']
        if (len(namesplit[0]) == 0):
            print("Error: First folder item is 0 in length")
            return

        if len(namesplit) == 1: #base case, assumed not duplicate
            self.items.append(dirElement(namesplit[0], recursive_parent))
        else:
            new_parent = recursive_parent + "/" + namesplit[0]
            for i in range(0, len(self.items)):
                if (self.items[i].dir_name == namesplit[0]):
                    namesplit.pop(0)
                    self.items[i].addElement(namesplit, new_parent)
                    return
            
            #if not found
            newElement = dirElement(namesplit[0], recursive_parent)
            self.items.append(newElement)
            namesplit.pop(0)
            newElement.addElement(namesplit, new_parent)


def Decryptor():

    config = readConfig()
    if (config == None):
        print("Error: Could not find config file.")
        while True: pass

    if (config['encrypted'].lower() != 'true'):
        print("Error: Files must first be encrypted.")
        while True: pass

    if ('iv' not in config):
        print("Error: Missing 'iv' value in config!")
        while True: pass

    salt = config['salt'] if ('salt' in config) else ""
    if len(salt) < 16: print("Warning: Value for salt should be defined.")

    while True:
        pw = salt + input("Enter your password: ")
        pwhash = hashlib.sha256(base64.b64encode(pw.encode('utf-8'))).hexdigest()

        if ('hashed_pw' in config and len(config['hashed_pw']) == 64):
            if hashlib.sha256(base64.b64encode((salt + pwhash).encode('utf-8'))).hexdigest() != config['hashed_pw']:
                print("Incorrect password.")
            else: break
        else: break

    success = False

    dirtree = dirElement(None, "")
    fernet = Fernet(base64.urlsafe_b64encode(bytes.fromhex(pwhash)[0:32])) #truncate key
    aes_cfb = Cipher(algorithms.AES(bytes.fromhex(pwhash)), mode=modes.CFB(bytes.fromhex(config['iv'])))

    print("Decrypting Files... (This may take a moment)")
    for (dir_path, dir_names, file_names) in os.walk(os.getcwd()):
        if not protected_directory(dir_path):
            for file in file_names:
                if not protected_file(file):
                    try:
                        content = None
                        with open(dir_path + "/" + file) as openFile:
                            content = openFile.read()
                        if content == None: raise Exception("Could not read content of file.")
                        
                        decrypted_file = decrypt(file, aes_cfb)

                        if (not isascii(decrypted_file)): raise Exception("Could not decrypt file name %s" % file) #wrong password

                        os.rename(dir_path + "/" + file, dir_path + "/" + decrypted_file)

                        if len(content) > 0:
                            decrypted = fernet.decrypt(content)
                            if (len(decrypted) > 0):
                                with open(dir_path + "/" + decrypted_file, 'wb') as openFile: openFile.write(decrypted)
                        success = True
                    except Exception as ex:
                        print("Could not decrypt %s" % file)
                        print(ex)
            dir_list = dir_path.replace(os.getcwd(), '', 1).replace('/', '\\').replace('\\\\', '\\').split("\\")
            if len(dir_list) > 1:
                dir_list.pop(0) #first item is empty str as long as relative_dir starts with /
                dirtree.addElement(dir_list)
    
    print("Decrypting Folder Names...")
    for parent_dir, dir_name in dirtree.getList():
        try:
            decrypted_filename = decrypt(dir_name, aes_cfb)
            if (not isascii(decrypted_filename)): raise Exception("Could not decrypt a folder name")
            os.rename("%s/%s/%s" % (os.getcwd(), parent_dir, dir_name), "%s/%s/%s" % (os.getcwd(), parent_dir, decrypted_filename))
        except:
            print("Error: Could not rename directory %s" % (os.getcwd() + "/" + parent_dir + "/" + dir_name))

    if success and ('save_key_file' in config and config['save_key_file'].lower() == 'true'):
        with open(os.getcwd() + "/key.config", 'w') as keyfile:
            keyfile.write(pwhash + "\n" + config['iv'] + "\n" + salt)
    
    if success:
        config['encrypted'] = 'false'
        config['hashed_pw'] = ''
        saveConfig(config)
    else: 
        while True: pass
    
    print("Done!")
    

                
if __name__ == "__main__":
    try:
        Decryptor()
    except Exception as ex:
        print("An error occured:")
        print(ex)
        while True: pass

