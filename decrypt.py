
import os, hashlib, base64, cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

def decrypt(text, key, iv):
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), mode=modes.CFB(bytes.fromhex(iv))).decryptor()
    return cipher.update(bytes.fromhex(text)).decode('latin-1') + cipher.finalize().decode('latin-1')

def decrypt_bytes(text, key, iv):
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), mode=modes.CFB(bytes.fromhex(iv))).decryptor()
    return cipher.update(bytes.fromhex(text)) + cipher.finalize()

def isascii(s):
    try:
        s.encode('ascii')
        return True
    except: return False


def Decryptor():

    config = readConfig()
    if (config == None):
        print("Error: Could not find config file.")
        while True: pass

    if (config['encrypted'].lower() != 'true'):
        print("Error: Files must first be encrypted.")
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

    save_key = True
    success = False

    #cipher = Cipher(algorithms.AES(bytes.fromhex(pwhash)), mode=modes.CFB(bytes.fromhex(config['iv']))).decryptor()

    for (dir_path, dir_names, file_names) in os.walk(os.getcwd()):
        if not (dir_path.__contains__(".git")):
            for file in file_names:
                if not (file == "decrypt.py" or file == "encrypt.py" or file == "encryption.config" or file == "key.config" 
                        or file.endswith(".pyc") or file.startswith(".noenc")):
                    try:
                        content = None
                        with open(dir_path + "/" + file) as openFile:
                            content = openFile.read()
                        if content == None: raise("Could not read content of file.")
                        
                        decrypted_file = decrypt(file, pwhash, config['iv'])

                        if (not isascii(decrypted_file)): raise Exception("Could not decrypt file name %s" % file) #wrong password

                        os.rename(file, decrypted_file)

                        if len(content) > 0:
                            decrypted = decrypt_bytes(content, pwhash, config['iv'])
                            if (len(decrypted) > 0):
                                with open(dir_path + "/" + decrypted_file, 'wb') as openFile: openFile.write(decrypted)
                        success = True
                    except Exception as ex:
                        save_key = False
                        print("Could not decrypt %s" % file)
                        print(ex)

    if save_key and ('save_key_file' in config and config['save_key_file'].lower() == 'true'):
        with open(os.getcwd() + "/key.config", 'w') as keyfile:
            keyfile.write(pwhash)
    
    if success:
        config['encrypted'] = 'false'
        config['hashed_pw'] = ''
        saveConfig(config)
    else: 
        while True: pass
    

                
if __name__ == "__main__":
    Decryptor()

