
'''
File Name: request.py
Dependencies: BaseHTTPRequestHandler

Description:
This module contains the HTTPRequestHandler class which is a subclass of BaseHTTPRequestHandler.
It is used to handle GET, POST, PUT, and DELETE requests. 
The class is used in the BaseServer class in server.py.

'''

from http.server import BaseHTTPRequestHandler

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        server_root = self.server._root
        print(f"Directory paths: {server_root}")

        headers = self.headers
        print(f"Headers: {headers}")

        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        message = "Hello, World! Here is a GET response"
        self.wfile.write(bytes(message, "utf8"))

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        message = "Hello, World! Here is a POST response"
        self.wfile.write(bytes(message, "utf8"))
    
    def do_PUT(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        message = "Hello, World! Here is a PUT response"
        self.wfile.write(bytes(message, "utf8"))
    
    def do_DELETE(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        message = "Hello, World! Here is a DELETE response"
        self.wfile.write(bytes(message, "utf8"))

