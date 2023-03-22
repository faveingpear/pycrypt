import socket

class server(socket.socket):

    def __init__(self, host, port) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)

        self.bind((host,port))

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
                print(data)
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
                return self.recv(4096)
            except ConnectionResetError:
                continue

    def close(self):
        self.close