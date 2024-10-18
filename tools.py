from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
import hashlib
import os

# print more message if debug_log is ture
debug_log = False

def log(*vals):
    """
        Log function for debug
    """
    if debug_log is False:
        return
    
    for v in vals:
        print(v, end=' ')
    print()
    return

####################################

# Generate RSA key pairs
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Export public and private keys
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem_public_key, pem_private_key

# encryption function
def encrypt_rsa(public_key:bytes, message:bytes) -> bytes:
    public_key = serialization.load_pem_public_key(
        public_key
    )
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Decryption function
def decrypt_rsa(private_key:bytes, encrypted_message:bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key, password=None
    )
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message

# def load_public_key_from_bytes(key: str|bytes):
#     return serialization.load_pem_public_key(key)


# def load_private_key_from_bytes(private_key_data: str|bytes):
#     return serialization.load_pem_private_key(private_key_data, password=None)


###############################################################
# Signature function
def __sign(private_key:bytes, message:bytes):
    salt_size = 32
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=salt_size
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature function
def __verify(public_key, message:bytes, signature:bytes):
    salt_size = 32
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=salt_size
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(e)
        return False

def msg_signature(private_key:bytes, data:dict, counter:int) -> str:
    data_json:str = json.dumps(data) + str(counter)
    signature:bytes = __sign(private_key, data_json.encode('utf-8'))
    encoded_signature = base64.b64encode(signature)
    return encoded_signature.decode()


def verify_msg_signature(public_key:bytes, encoded_signature:str, data:dict, counter:int):
    data_json:str = json.dumps(data) + str(counter)
    signature = base64.b64decode(encoded_signature.encode('utf-8'))
    return __verify(public_key, data_json.encode('utf-8'), signature)


##############################################################
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json
import base64


def generate_aes_key():
    return get_random_bytes(16)

# AES encryption
def encrypt_aes(key:bytes, plain_text:bytes) -> tuple[bytes, bytes]:
    if type(plain_text) == str:
        plain_text = plain_text.encode()
    
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(16)
    # Creating an AES Encryptor
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Padding the plaintext
    padded_text = pad(plain_text, AES.block_size)
    # encryption
    encrypted_text = cipher.encrypt(padded_text)
    # Returns IV and ciphertext
    return iv, encrypted_text

# AES Decryption
def decrypt_aes(key:bytes, iv:bytes, encrypted_text:bytes) -> bytes:
    if type(encrypted_text) != bytes:
        print('aes_decrypt() function argument encrypted_text must have type bytes')
        exit(1)
    
    # Extract ciphertext
    cipher_text = encrypted_text
    # Creating an AES Decryptor
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt and remove padding
    decrypted_bytes = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_bytes


def get_fingerprint(public_key:bytes) -> str:
    sha256_str = hashlib.sha256(public_key).hexdigest()
    fingerprint = base64.b64encode(sha256_str.encode('utf-8'))
    return fingerprint.decode()



def init_dirs():
    for path in ['downloads', 'uploads']:
        if not os.path.exists(path):
            os.mkdir(path)
            
    return



###############################################################
# test functions

def test1():
    public_key, private_key = generate_rsa_keys()

    message = b"Hello, RSA!"

    encrypted_message = encrypt_rsa(public_key, message)
    print(f"Encrypted message: {encrypted_message}")

    decrypted_message = decrypt_rsa(private_key, encrypted_message)
    print(f"Decrypted message: {decrypted_message.decode('utf-8')}")




def test2():
    public_key, private_key = generate_rsa_keys()

    message = b"Hello, RSA!"

    signature = __sign(private_key, message)
    print(f"Signature: {signature}")

    is_valid = __verify(public_key, message, signature)
    print(f"Is the signature valid? {is_valid}")


def test3():
    key = generate_aes_key()

    data = b"Hello, AES!"

    iv, encrypted_data = encrypt_aes(key, data)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt_aes(key, iv, encrypted_data)
    print(f"Decrypted data: {decrypted_data.decode('utf-8')}")


if __name__ == "__main__":
    # test3()
    # pem_public_key, pem_private_key = generate_rsa_keys()
    # data = {
    #     'public_key': pem_public_key.decode('utf-8'),
    #     'private_key': pem_private_key.decode('utf-8')
    # }
    # print(json.dumps(data))

    init_dirs()

init_dirs()