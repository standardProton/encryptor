#!/usr/bin/env python3
"Secure offline directory encryptor and decryptor"

import os, hashlib, base64, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from decrypt import *
from getpass import getpass
import threading
import queue

def encrypt(text, aes_cfb):
    cipher = aes_cfb.encryptor()
    return bytes.hex(cipher.update(text.encode('utf-8')) + cipher.finalize())

def encryptor_thread(q: queue.Queue):

    while True:
        dir_path, file = q.get()
        if (dir_path is None or file is None): break
        
        if (not isascii(file)):
            print("Error: File name must be ASCII-encoded before encryption (%s)" % file)
            continue
        try:
            content = None
            with open(dir_path + "/" + file, mode='rb') as openFile:
                content = openFile.read()
            if (content != None):
                if (len(content) > 0):
                    encrypted = fernet.encrypt(content).decode()
                    if len(encrypted) > 0: 
                        with open(dir_path + "/" + file, mode='w') as openFile: 
                            openFile.write(encrypted)
                
                os.rename(dir_path + "/" + file, dir_path + "/" + encrypt(file, aes_cfb))
            else: raise Exception("Could not read content of file.")
        except Exception as ex:
            print("Could not encrypt %s" % file)
            print(ex)
        
if __name__ == "__main__":
    try:
        config = readConfig()

        if (config == None): err("Error: Could not find config file.")
        if (config['encrypted'].lower() != 'false'): err("Error: Files must first be decrypted.")

        key, salt = None, None
        if ('salt' in config and len(config['salt']) > 0): 
            salt = bytes.fromhex(config['salt'].strip())
            if len(salt) < 16: print("Warning: Salt value should be at least 16 bytes long.")
        else: 
            salt = os.urandom(24)
            config['salt'] = bytes.hex(salt)
            config['iv'] = bytes.hex(os.urandom(16))

        if (os.path.exists("key.config")):
            with open(os.getcwd() + "/key.config", 'rb') as keyfile:
                key = keyfile.read()
                if (len(key) != 32): err("Invalid key.config length")
            with open(os.getcwd() + "/key.config", 'wb') as keyfile:
                keyfile.write(os.urandom(16384))  #overwrite the real key before deleting
            os.remove(os.getcwd() + "/key.config")
        
        if key == None:
            while True:
                pw = getpass("Enter your password: ").strip()
                if len(pw) > 0:
                    pw2 = getpass("Confirm password: ").strip()
                    if not (pw == pw2): print("Passwords do not match")
                    else:
                        key = derivePassword(pw, salt)
                        break

        config['encrypted'] = 'true'
        config['hashed_pw'] = bytes.hex(derivePassword(base64.b64encode(key).decode(), salt))
        saveConfig(config)

        dirtree = dirElement(None, "")
        fernet = Fernet(base64.b64encode(key))
        aes_cfb = Cipher(algorithms.AES(key), mode=modes.CFB(bytes.fromhex(config['iv'])))

        print("Encrypting Files...")

        q = queue.Queue()
        encryptor_threads = []
        for i in range(NUM_THREADS): #start threads
                thd = threading.Thread(target=encryptor_thread, args=[q])
                thd.start()
                encryptor_threads.append(thd)

        for (dir_path, dir_names, file_names) in os.walk(os.getcwd()):
            if not protected_directory(dir_path):
                for file in file_names:
                    if (not protected_file(file)):
                        q.put((dir_path, file))
                dir_list = dir_path.replace(os.getcwd(), '', 1).replace('/', '\\').replace('\\\\', '\\').split("\\")
                if len(dir_list) > 1:
                    dir_list.pop(0) #first item is empty str as long as relative_dir starts with /
                    dirtree.addElement(dir_list)
                    
        for i in range(NUM_THREADS): q.put((None, None)) #poison pill
        for thd in encryptor_threads: thd.join()

        print("Encrypting Folder Names...")
        for parent_dir, dir_name in dirtree.getList():
            try:
                os.rename("%s/%s/%s" % (os.getcwd(), parent_dir, dir_name), "%s/%s/%s" % (os.getcwd(), parent_dir, encrypt(dir_name, aes_cfb)))
            except:
                print("Error: Could not rename directory %s" % (os.getcwd() + "/" + parent_dir + "/" + dir_name))

        print("Done!")

    except Exception as ex:
        print(ex)
        err("An error occured!")