import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class KeyPair():

    def __init__(self, keysize:int) -> None:

        self.public, self.private = self.__genKeys(keysize=keysize)

    def __genKeys(self,keysize=None) -> tuple[str,str]:
        #rsa.PublicKey.__str__
        return rsa.newkeys(keysize)
    
    def getPublic(self):
        return self.public

    def getPrivate(self):
        return self.private
    
def symEncrypt(data) -> tuple[str,str,str]:
        key = get_random_bytes(16)
        print("KEY:")
        print(key)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        return ciphertext, key, tag, nonce

def symDecrypt(encdata, key, tag, nonce):
     
     cipher = AES.new(key, AES.MODE_EAX, nonce)
     data = cipher.decrypt_and_verify(encdata, tag)
     return data

# class Encrypt():

#     def __init__(self) -> None:
#         pass

#     def encrypt(self, data, keypair:KeyPair):
#         chiphertext, symKey = self.__symEncrypt(data=data)
#         encKey = self.__AsymEncrypt(symKey, keypair=keypair)
#         return encKey, chiphertext

#     def __symEncrypt(self, data) -> tuple[str,str]:
#         key = get_random_bytes(16)
#         cipher = AES.new(key, AES.MODE_EAX)
#         ciphertext, tag = cipher.encrypt_and_digest(data)
#         return ciphertext, key

#     def __AsymEncrypt(self, data, keypair:KeyPair) -> str:
#         encData = rsa.encrypt(data, keypair.getPublic())
#         return encData

# def main():
#     keys = KeyPair(2048, public=None, private=None)
#     encryption = Encrypt()
#     print(encryption.encrypt(data=b'Hello!', keypair=keys))
    
# if __name__ == "__main__":
#     main()