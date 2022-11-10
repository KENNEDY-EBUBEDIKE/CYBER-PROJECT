from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from binascii import hexlify, unhexlify


def generate_shared_secret(required_share, share_split):
    key = get_random_bytes(16)
    shares = Shamir.split(required_share, share_split, key, ssss=False)
    return shares, key


def retrieve_shared_key(shares):
    key = Shamir.combine(shares, ssss=False)
    return key


def encrypt_file(file, key):
    content = open(file.document.path, 'rb').read()
    salt = get_random_bytes(32)
    main_key = PBKDF2(password=key, salt=salt, dkLen=32)

    cipher = AES.new(key=main_key, mode=AES.MODE_EAX)
    encrypted_content, tag = cipher.encrypt_and_digest(content)

    outfile = open(file.document.path, 'wb')
    [outfile.write(x) for x in (salt, cipher.nonce, tag, encrypted_content)]
    outfile.close()
    return file


def decrypt_file(file, key):

    infile = open(file.document.path, 'rb')
    salt = infile.read(32)
    nonce = infile.read(16)
    tag = infile.read(16)
    encrypted_content = infile.read()
    infile.close()

    main_key = PBKDF2(password=key, salt=salt, dkLen=32)
    cipher = AES.new(key=main_key, mode=AES.MODE_EAX, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(ciphertext=encrypted_content, received_mac_tag=tag)

    file_name = file.document.path
    open(file_name, "wb").write(decrypted_content)

    return file
