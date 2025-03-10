import os, hashlib, base64, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

        if (config == None):
            print("Error: Could not find config file.")
            while True: pass

        if (config['encrypted'].lower() != 'false'):
            print("Error: Files must first be decrypted.")
            while True: pass

        if ('iv' not in config):
            print("Error: Missing 'iv' value in config!")
            while True: pass
        
        pwhash = None
        salt = config['salt'] if ('salt' in config) else ""
        if len(salt) < 16: print("Warning: Value for salt should be defined.")

        if (os.path.exists("key.config")):
            with open(os.getcwd() + "/key.config") as keyfile:
                lines = keyfile.readlines()
                if len(lines) > 2 and len(lines[0]) == 65:
                    if (lines[1].replace('\n', '') == config['iv'] and lines[2].replace('\n', '') == salt):
                        pwhash = lines[0].replace('\n', '')
            for i in range(0, 4):
                with open(os.getcwd() + "/key.config", 'w') as keyfile:
                    keyfile.write(binascii.b2a_hex(os.urandom(2048)).decode("utf-8"))  #overwrite the real key before deleting
            os.remove(os.getcwd() + "/key.config")
        
        if pwhash == None:
            while True:
                pw = getpass("Enter your password: ").strip()
                if len(pw) > 0:
                    print("\n\n\nConfirm password: %s" % pw)
                    confirm = input("[Y/n]: ").lower()
                    if (confirm == "y" or confirm == "yes"): 
                        pwhash = hashlib.sha256(base64.b64encode((salt + pw).encode())).hexdigest()
                        break

        config['encrypted'] = 'true'
        config['hashed_pw'] = hashlib.sha256(base64.b64encode((salt + pwhash).encode())).hexdigest()
        saveConfig(config)

        dirtree = dirElement(None, "")
        fernet = Fernet(base64.urlsafe_b64encode(bytes.fromhex(pwhash)[0:32])) #truncate key
        aes_cfb = Cipher(algorithms.AES(bytes.fromhex(pwhash)), mode=modes.CFB(bytes.fromhex(config['iv'])))

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
        print("An error occured:")
        print(ex)
        while True: pass