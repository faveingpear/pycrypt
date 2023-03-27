import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import socket
import sys
import getopt

import traceback

import json
import base64

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
        #print("KEY:")
        #print(key)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        return ciphertext, key, tag, nonce

def symDecrypt(encdata, key, tag, nonce):
     
     cipher = AES.new(key, AES.MODE_EAX, nonce)
     data = cipher.decrypt_and_verify(encdata, tag)
     return data

class server(socket.socket):

    def __init__(self, host, port) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)

        self.bind((host,port))

        #print("Bound on now waiting for connections")
        while True:
            try:
                self.listen()
                self.__conn, self.__addr = self.accept()
                break
            except ConnectionResetError:
                continue

    def send(self,data):
        while True:
            try:
                #print(data)
                self.__conn.sendall(data)
                break
            except ConnectionResetError:
                continue

    def receive(self):
        while True:
            try:
                return self.__conn.recv(4096)
            except ConnectionResetError:
                continue

    def close(self):
        self.close

class client(socket.socket):

    def __init__(self, host, port) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)

        while True:
            try:
                self.connect((host, port))
                break
            except ConnectionResetError:
                continue
    
    def send(self,data):
        while True:
            try:
                self.sendall(data)
                break
            except ConnectionResetError:
                continue

    def receive(self):
        while True:
            try:
                return self.recv()
            except ConnectionResetError:
                continue

    def close(self):
        self.close

def startClient(host, port, infile, outfile):
    print("Connecting to the server on host: " + host + " port: " + str(port))
    s = client(host,port)
    print("Conncected")

    print("Creating key pair")
    receiverKeyPair = KeyPair(2048)

    print("Receiving public key")
    senderPublicKey = rsa.PublicKey.load_pkcs1(s.receive(), "PEM")
    
    print("Sending public key")
    s.send(receiverKeyPair.getPublic().save_pkcs1("PEM"))

    packet = json.loads(s.receive())

    encdata = base64.b64decode(packet["encdata"].encode("utf-8"))
    enckey = base64.b64decode(packet["enckey"].encode("utf-8"))
    enctag = base64.b64decode(packet["enctag"].encode("utf-8"))
    encnonce = base64.b64decode(packet["encnonce"].encode("utf-8"))

    s.close()

    try:

        key = rsa.decrypt(enckey, receiverKeyPair.private)
        tag = rsa.decrypt(enctag, receiverKeyPair.private)
        nonce = rsa.decrypt(encnonce, receiverKeyPair.private)

        data = symDecrypt(encdata, key, tag, nonce)

            
        file = open(outfile, "x")
        file.write(data.decode("utf-8"))
        file.close()

    except rsa.pkcs1.DecryptionError as e:
        print("decrypting error?")
        traceback.print_exception(e)
        print(enckey)
        s.close()
        exit


def startServer(host, port, infile, outfile):
    print("Connecting to the client on host: " + host + " port: " + str(port))
    #print(port)
    s = server(host,port)
    print("Connected")

    print("Creating key pair")
    clientKeyPair = KeyPair(2048)

    print("Sending Public Key")
    s.send(clientKeyPair.getPublic().save_pkcs1("PEM"))

    print("Receiving Public Key")
    receiverPublicKey = rsa.PublicKey.load_pkcs1(s.receive(), "PEM")
    
    print("Reading file")
    file = open(infile, "rb")
    data = file.read()
    file.close()

    print("Encrypting the data")
    encdata, key, tag, nonce = symEncrypt(data)
    enckey = rsa.encrypt(key, receiverPublicKey)
    enctag = rsa.encrypt(tag, receiverPublicKey)
    encnonce = rsa.encrypt(nonce, receiverPublicKey)

    packetData = {
        "encdata": base64.b64encode(encdata).decode("utf-8"),
        "enckey": base64.b64encode(enckey).decode("utf-8"),
        "enctag": base64.b64encode(enctag).decode("utf-8"),
        "encnonce": base64.b64encode(encnonce).decode("utf-8")
    }
    #base64.encodebytes()
    print("Sending encoded data")
    s.send(json.dumps(packetData).encode("utf-8"))

    # s.send(encdata)
    # print(enckey)
    # s.send(enckey)
    # s.send(rsa.encrypt(tag, receiverPublicKey))
    # s.send(rsa.encrypt(nonce, receiverPublicKey))

    s.close()



def main(argv):
    args = sys.argv

    server = False
    client = False

    host = None
    port = None

    infile = None
    outfile = None

    opts, args = getopt.getopt(argv, "hscH:P:i:o:", ["help","server", "client", "host=", "port=", "infile=", "outfile="])

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("SERVER: pycrypt.py -s -H 127.0.0.1 -P 30000 -i FILE")
            print("CLIENT: pycrypt.py -c -H 127.0.0.1 -P 30000 -o FILE")
        elif opt in ("-s", "--server"):
            server = True
            if client == True:
                print("Program cannot be both a client or and server")
        elif opt in ("-c", "--client"):
            client = True
            if server == True:
                print("Program cannot be both a client or and server")
        elif opt in ("-H", "--host"):
            host = arg
        elif opt in ("-P", "--port"):
            port = int(arg)
        elif opt in ("-i", "--infile"):
            infile = arg
        elif opt in ("-o", "--outfile"):
            outfile = arg

    if host == None or port == None:
        print("Please enter a host or port")
    # if infile == None or outfile == None:
    #     print("Please add a intput file or output file")

    if server == True:
        startServer(host, port, infile, outfile)
    if client == True:
        startClient(host, port, infile, outfile)

if __name__ == "__main__":
    main(sys.argv[1:])