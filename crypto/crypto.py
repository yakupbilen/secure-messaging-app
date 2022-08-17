import rsa
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad


class Crypto:
    def get_key(self):
        return os.urandom(32)

    def encrypt(self,data,rec_public,aes_key=None):
        if not aes_key:
            aes_key = self.get_key()
        cipher_text = AES.new(aes_key,AES.MODE_ECB).encrypt(pad(data, 16))
        aes_key_encrypted = rsa.encrypt(aes_key,rec_public)
        return cipher_text,aes_key_encrypted,aes_key

    def decrypt(self,cipher_text,cipher_aes,private):
        aes_key = rsa.decrypt(cipher_aes,private)
        plain_text = unpad(AES.new(aes_key,AES.MODE_ECB).decrypt(cipher_text),16)
        return plain_text
