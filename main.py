# Exercices the rsa.py module.
# Tyler Mumford, 2015

import rsa

def choose():
    rsa.logfile.flush()
    return input("""\
    D: Decrypt a message
    E: Encrypt a message
    K: Create new key files
    Q: Quit

    Enter the letter of your choice: """).upper()

def create_new_key_files():
    passphrase = input("    Enter a passphrase to seed key files: ")
    private_key, public_key = rsa.generate_keys(passphrase)

    private_file = open("private.key.txt", mode="wt")
    public_file = open("public.key.txt", mode="wt")

    private_file.write("{}\n{}".format(private_key[0], private_key[1]))
    public_file.write("{}\n{}".format(public_key[0], public_key[1]))

    private_file.close()
    public_file.close()

    return private_key, public_key

def load_key_files():
    private_file = open("./private.key.txt", mode="rt")
    public_file = open("./public.key.txt", mode="rt")

    private_key = tuple([int(line.strip()) for line in private_file])
    public_key = tuple([int(line.strip()) for line in public_file])
    
    private_file.close()
    public_file.close()

    assert int(public_key[1]) > 0
    return private_key, public_key

# 
# Main program logic
# 

choice = choose()
while choice != "Q":
    if choice == "D":
        private_key, public_key = load_key_files()
        ciphertext = input("    Enter ciphertext to decrypt:\n").strip()
        plaintext = rsa.decrypt(ciphertext, private_key)
        print("    Decrypted:\n{}".format(plaintext))
    elif choice == "E":
        private_key, public_key = load_key_files()
        plaintext = input("    Enter plaintext to encrypt:\n").strip()
        ciphertext = rsa.encrypt(plaintext, public_key)
        print("    Encrypted:\n{}".format(ciphertext))
    elif choice == "K":
        create_new_key_files()
    else:
        print("    Sorry, that doesn't appear to be a valid choice.\n")

    print()
    choice = choose()
