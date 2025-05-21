
# File Encryptor

This is a simple, secure, offline, and open-source way to cryptographically store and retrieve your important files. Use this software to securely store passwords, 2FA backup codes, journalism, or other important documents. Since this is completely offline, it reduces your risk of your data being exposed if a centralized service is breached. It is important that the main password is unique and never written anywhere else.

The system uses python Fernet to symmetrically encrypt and decrypt the files that exist in the same directory as the .py files. If you don't want a file to be encrypted, its name needs to be prefixed with ".noenc".

## Setup

1. Run `pip install cryptography`
2. If your filesystem uses Copy-On-Write (such as BTRFS), you must disable this in the directory you intend to encrypt and decrypt files. Use `chattr +C /path/where/encryption/` BEFORE adding any files into the path if this applies to you. [More Info](https://wiki.archlinux.org/title/Btrfs)
3. Optionally set `save_key_file` in config. If set to true, it saves an unencrypted key file so you don't need to re-type your password every time. This file is overwritten before deletion when you go to encrypt again.
4. Recommended to delete the `.git` directory or just copy and paste the files you need so git doesn't accidentally track unencrypted files.
5. Set permissions for the python files to read and execute only (Ex. `sudo chmod 555 encrypt.py decrypt.py`) and optionally chown them to root user. Recommended to recursively set all other files to read/write only for your user. 

## Instructions to update

1. Decrypt your files with `python ./decrypt --no-keyfile` to prevent a key written to disk. Your files must be unencrypted to update the python scripts.
2. Bring in the new file versions. If you do this with git, make sure it is not tracking your unencrypted files.
3. Re-encrypt as normal, it will ask for your password again.

You may generate a new random iv or salt by emptying the value from the config while in the unencrypted state. Don't edit the iv or salt while files are still encrypted. You can set a new password by decrypting with the `--no-keyfile` flag and then encrypting again.

Privacy is a human right.