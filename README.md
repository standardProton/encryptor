
This is a simple, secure, offline, and open-source way to cryptographically store and retrieve your important files. Use this software to securely store passwords, 2FA backup codes, journalism, or other important documents. It is necessary to use software that is offline and open-source to prevent centralization of the master passwords and ensure your security. It is important that the master password is unique and never written anywhere else in plaintext on your devices. Remember, the most secure information is information that doesn't exist, so memorize your key and only write it on paper placed in a physical vault. 

The system uses AES to symmetrically encrypt and decrypt the files that exist in the same directory as the .py files. Currently, the name and content of files get encrypted, but not the names of folders. If you don't want a file to be encrypted, its name needs to start with ".noenc". A hash of the password you type in is used as the encryption key. To get started, make sure you have the necessary python libraries by running:

pip install cryptography

Configuration value explanations:
- 'encrypted': A boolean to quickly see if the files in the directory have already been encrypted.
- 'save_key_file': If true, a key is stored so you don't have to re-enter it when re-encrypting. The key file is overwritten and permanently deleted upon encryption.
- 'iv': Initialization vector for AES encryption. It is just as secure using the default value, but you can change it to any random 16 hexadecimal bytes if necessary.
- 'salt': Used in hashing to prevent lookup attacks. It is secure with the default value, but it is recommended to change this to any 16 or more random characters.
- 'hashed_pw': A salted hash of the encryption key. This is NOT the encryption key itself, and is only used to quickly verify if the correct password is entered in decrypt.py.

Important: The 'iv' and 'salt' values should only be edited when files are in the unencrypted state. Store a backup of these values if you change them from the defaults. 


