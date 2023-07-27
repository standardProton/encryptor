import os, hashlib, base64, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from decrypt import *

def encrypt_bytes(text, key, iv):
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), mode=modes.CFB(bytes.fromhex(iv))).encryptor()
    return bytes.hex(cipher.update(text) + cipher.finalize())

def encrypt(text, key, iv):
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), mode=modes.CFB(bytes.fromhex(iv))).encryptor()
    return bytes.hex(cipher.update(text.encode('utf-8')) + cipher.finalize())


def Encryptor():

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
            pw = input("Enter your password: ").strip()
            if len(pw) > 0:
                print("\n\n\nConfirm password: %s" % pw)
                confirm = input("[Y/n]: ").lower()
                if (confirm == "y" or confirm == "yes"): 
                    pwhash = hashlib.sha256(base64.b64encode((salt + pw).encode('utf-8'))).hexdigest()
                    break

    config['encrypted'] = 'true'
    config['hashed_pw'] = hashlib.sha256(base64.b64encode((salt + pwhash).encode('utf-8'))).hexdigest()
    saveConfig(config)

    for (dir_path, dir_names, file_names) in os.walk(os.getcwd()):
        if not (dir_path.__contains__(".git") or dir_path.__contains__("__pycache__") or dir_path.__contains__(".noenc")):
            for file in file_names:
                if not (file == "decrypt.py" or file == "encrypt.py" or file == "encryption.config" or file == ".gitignore"
                        or file.endswith(".pyc") or file.startswith(".noenc")):
                    if (not isascii(file)):
                        print("Error: File name must be ASCII-encoded before encryption (%s)" % file)
                        continue
                    try:
                        content = None
                        with open(dir_path + "/" + file, mode='rb') as openFile:
                            content = openFile.read()
                        if (content != None):
                            if (len(content) > 0):
                                encrypted = encrypt_bytes(content, pwhash, config['iv'])
                                if len(encrypted) > 0: 
                                    with open(dir_path + "/" + file, mode='w') as openFile: 
                                        openFile.write(encrypted)
                            
                            os.rename(dir_path + "/" + file, dir_path + "/" + encrypt(file, pwhash, config['iv']))
                        else: raise Exception("Could not read content of file.")
                    except Exception as ex:
                        print("Could not encrypt %s" % file)
                        print(ex)

if __name__ == "__main__":
    try:
        Encryptor()
    except Exception as ex:
        print("An error occured:")
        print(ex)
        while True: pass