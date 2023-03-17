# Write your script here
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import CMAC
from Crypto.Hash import SHA3_256
from Crypto.Signature import DSS
#from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from timeit import default_timer as timer
from cryptography.hazmat.primitives.asymmetric import utils
import rsa

class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here
        symmetric_key = get_random_bytes(16)
   
        public_key_sender_rsa,private_key_sender_rsa = rsa.newkeys(2048)
  
        public_key_receiver_rsa,private_key_receiver_rsa = rsa.newkeys(2048)
  
        private_key_sender_ecc = ec.generate_private_key(ec.SECP384R1())
        public_key_sender_ecc = private_key_sender_ecc.public_key()

        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here
        nonce_aes_cbc = get_random_bytes(16)
        nonce_aes_ctr = get_random_bytes(8)
        nonce_encrypt_rsa = get_random_bytes(256)
        nonce_aes_cmac = get_random_bytes(16)
        nonce_hmac = get_random_bytes(32)
        nonce_tag_rsa = get_random_bytes(32)
        nonce_ecdsa = get_random_bytes(32)
        nonce_aes_gcm = get_random_bytes(8)


        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here


        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            cipher = AES.new(key,AES.MODE_CBC,nonce)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'),AES.block_size))

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            cipher = AES.new(key,AES.MODE_CTR,nonce=nonce)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            ciphertext = rsa.encrypt(plaintext,key)
            
        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here


        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here
            aes = AES.new(key, AES.MODE_CBC, nonce)
            plaintext = unpad(aes.decrypt(ciphertext), AES.block_size)
            plaintext = plaintext.decode('utf-8')

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
            plaintext = aes.decrypt(ciphertext)
            plaintext = plaintext.decode('utf-8')
            
        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            plaintext = rsa.decrypt(ciphertext,key)

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            auth = CMAC.new(key, ciphermod=AES)
            auth.update(plaintext.encode('utf-8'))
            auth_tag=auth.digest()

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            auth = SHA3_256.new()
            auth.update(plaintext.encode('utf-8'))
            auth_tag = auth.digest()

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            auth = SHA3_256.new()
            auth.update(plaintext.encode('utf-8'))
            auth_tag = rsa.sign(auth.digest(),key, 'SHA-256')

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            hash = hashes.SHA256()
            hash_o =hashes.Hash(hash)
            hash_o.update(plaintext.encode('utf-8'))
            digestM = hash_o.finalize()
            auth_tag = key.sign(digestM,ec.ECDSA(utils.Prehashed(hash)))
            

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            auth = CMAC.new(key, ciphermod=AES)
            auth.update(plaintext.encode('utf-8'))
            calc_auth_tag = auth.digest()
            if auth_tag == calc_auth_tag :
                auth_tag_valid = True
            else :
                auth_tag_valid = False

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            auth = SHA3_256.new()
            auth.update(plaintext.encode('utf-8'))
            calc_auth_tag = auth.digest()
            if auth_tag == calc_auth_tag :
                auth_tag_valid = True
            else :
                auth_tag_valid = False

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            auth = SHA3_256.new()
            auth.update(plaintext.encode('utf-8'))
            if rsa.verify(auth.digest(),auth_tag,key):
                auth_tag_valid = True
            else :
                auth_tag_valid = False

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            hash = hashes.SHA256()
            hash_o = hashes.Hash(hash)
            hash_o.update(plaintext.encode('utf-8'))
            digestM = hash_o.finalize()
            try :
                key.verify(auth_tag,digestM,ec.ECDSA(utils.Prehashed(hash)))
                auth_tag_valid = True
            except:
                auth_tag_valid = False

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            aes = AES.new(key_encrypt, AES.MODE_GCM, nonce=nonce)
            ciphertext, auth_tag = aes.encrypt_and_digest(plaintext.encode('utf-8'))

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here

        

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            aes = AES.new(key_decrypt, AES.MODE_GCM, nonce=nonce)
            plaintext = aes.decrypt(ciphertext)
            plaintext = plaintext.decode('utf-8')
            try:
                aes.verify(auth_tag)
                auth_tag_valid = True
            except ValueError:
                auth_tag_valid = False

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '_main_': # Do not change this
    ExecuteCrypto() # Do not change this