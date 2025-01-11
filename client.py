

class Client():
    def __init__(self, server):
        self.server = server

    def send(self, message):
        self.server.receive(message)
