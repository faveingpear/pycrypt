import encrypt
from sockets import server
import rsa

HOST="127.0.0.1"
PORT=65432  

clientKeyPair = encrypt.KeyPair(2048)

# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.bind((HOST, PORT))

s = server(HOST,PORT)

print("Sending Public Key")
s.send(clientKeyPair.getPublic().save_pkcs1("PEM"))
print("------")
print("Receiving Public Key")
receiverPublicKey = rsa.PublicKey.load_pkcs1(s.receive(), "PEM")

data = input("Enter data you want to send: ").encode("utf-8")

encdata, key, tag, nonce = encrypt.symEncrypt(data)
s.send(encdata)
enckey = rsa.encrypt(key, receiverPublicKey)
print("ENCKEY")
print(enckey)
s.send(enckey)
s.send(rsa.encrypt(tag, receiverPublicKey))
s.send(rsa.encrypt(nonce, receiverPublicKey))

#print(receiverPublicKey)

s.close()