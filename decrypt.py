#!/usr/bin/env python3
"Secure offline directory encryptor and decryptor"

import os, hashlib, base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from getpass import getpass
import threading
import queue

NUM_THREADS = 8
DEBUG = True #ignore .git
NOENC_PREFIX = ".noenc"

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

def derivePassword(pw, salt):
    pw = pw.strip()
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
    return kdf.derive(pw.encode('utf-8'))

def saveConfig(config):
    cstr = ""
    for key, value in config.items(): cstr += key + "=" + value + "\n"
    with open(os.getcwd() + "/encryption.config", 'w') as f: f.write(cstr)

def decrypt(text, aes_cfb):
    cipher = aes_cfb.decryptor()
    return cipher.update(bytes.fromhex(text)).decode('latin-1') + cipher.finalize().decode('latin-1')

def isascii(s):
    try:
        s.encode('ascii')
        return True
    except: return False

def protected_directory(dir_path):
    return dir_path.__contains__(NOENC_PREFIX) or (DEBUG and dir_path.__contains__(".git"))

def protected_file(file):
    return file == "decrypt.py" or file == "encrypt.py" or file == "encryption.config" \
        or (DEBUG and file == ".gitignore") or file.startswith(NOENC_PREFIX)

def err(s):
    print(s)
    while True: pass

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


def decryptor_thread(q: queue.Queue, status, fernet, aes_cfb): #mutable status

    while True:
        dir_path, file = q.get()
        if (dir_path is None or file is None or status[0] == -1): break
    
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
            status[0] = 1
        except Exception as ex:
            if (type(ex) == UnicodeDecodeError): 
                print("Incorrect password")
                status[0] = -1
                break
            print("Could not decrypt %s" % file)
            print(ex)
            continue

if __name__ == "__main__":
    try:
        config = readConfig()
        if (config == None): err("Error: Could not find config file.")
        if (config['encrypted'].lower() != 'true'): err("Error: Files must first be encrypted.")
        if ('iv' not in config): err("Error: Missing 'iv' value in config!")

        salt = bytes.fromhex(config['salt'])
        if len(salt) < 16: print("Warning: Salt value should be at least 16 bytes long.")

        while True:
            key = derivePassword(getpass("Enter your password: "), salt)

            if ('hashed_pw' in config):
                print("Checking password...")
                if (config['hashed_pw'] == bytes.hex(derivePassword(base64.b64encode(key).decode(), salt))): break
                else: print("Incorrect password")
            else: break

        status = [0] #mutable obj
        dirtree = dirElement(None, "")
        fernet = Fernet(base64.b64encode(key)) #truncate key
        aes_cfb = Cipher(algorithms.AES(key), mode=modes.CFB(bytes.fromhex(config['iv'])))

        print("Decrypting Files...")
        q = queue.Queue()
        decryptor_threads = []
        for i in range(NUM_THREADS):
            thd = threading.Thread(target=decryptor_thread, args=[q, status, fernet, aes_cfb])
            thd.start()
            decryptor_threads.append(thd)

        for (dir_path, dir_names, file_names) in os.walk(os.getcwd()):
            if (status[0] == -1): break
            if not protected_directory(dir_path):
                for file in file_names:
                    if not protected_file(file) and status[0] >= 0:
                        q.put((dir_path, file))
                dir_list = dir_path.replace(os.getcwd(), '', 1).replace('/', '\\').replace('\\\\', '\\').split("\\") #formatting
                if len(dir_list) > 1:
                    dir_list.pop(0) #first item is empty str as long as relative_dir starts with /
                    dirtree.addElement(dir_list)

        for i in range(NUM_THREADS): q.put((None, None)) #poison pill
        for thd in decryptor_threads: thd.join()

        if (status[0] == 1):
            print("Decrypting Folder Names...")
            for parent_dir, dir_name in dirtree.getList():
                try:
                    decrypted_filename = decrypt(dir_name, aes_cfb)
                    if (not isascii(decrypted_filename)): raise Exception("Could not decrypt a folder name")
                    os.rename("%s/%s/%s" % (os.getcwd(), parent_dir, dir_name), "%s/%s/%s" % (os.getcwd(), parent_dir, decrypted_filename))
                except:
                    print("Error: Could not rename directory %s" % (os.getcwd() + "/" + parent_dir + "/" + dir_name))

            if ('save_key_file' in config and config['save_key_file'].lower() == 'true' and not sys.argv.__contains__("--no-keyfile")):
                with open(os.getcwd() + "/key.config", 'wb') as keyfile: keyfile.write(key)
            
            config['encrypted'] = 'false'
            config['hashed_pw'] = ''
            saveConfig(config)
        else: 
            print("Failed to decrypt files")

        print("Done!")

    except Exception as ex:
        print(ex)
        err("An error occured!")

