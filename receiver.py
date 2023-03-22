import encrypt
from sockets import client
import rsa
import time

HOST="127.0.0.1"
PORT=65432  
        
receiverKeyPair = encrypt.KeyPair(2048)

#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = client(HOST,PORT)
print("Receiving Public Key")
senderPublicKey = rsa.PublicKey.load_pkcs1(s.receive(), "PEM")
print(senderPublicKey)
print("------")
print("Sending Public Key")
s.send(receiverKeyPair.getPublic().save_pkcs1("PEM"))

encdata = s.receive()
enckey = s.receive()
enctag = s.receive()
encnonce = s.receive()
print("KEY")
print(enckey)
print("DATA")
print(encdata)
key = rsa.decrypt(enckey, receiverKeyPair.private)
tag = rsa.decrypt(enctag, receiverKeyPair.private)
nonce = rsa.decrypt(encnonce, receiverKeyPair.private)

print(encrypt.symDecrypt(encdata, key, tag, nonce))
s.close()