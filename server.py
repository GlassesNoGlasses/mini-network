
import os
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
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


class BaseServer(HTTPServer):

    def __init__(self, dir_paths: list[str], server_address, RequestHandlerClass, bind_and_activate = True):
        try:
            invalid_paths = [path for path in dir_paths if not os.path.isdir(path)]

            if invalid_paths:
                raise FileNotFoundError(f"Invalid directory paths: {invalid_paths}")
            
        except FileNotFoundError:
            print(f"Invalid directory paths: {invalid_paths}. Would you like to create them? (y/n)")
            response = input()[0].lower() if input() else 'n'

            if response == 'y':
                for path in invalid_paths:
                    os.makedirs(path)
                print(f"Created directories: {invalid_paths}")
        
        self.dir_paths = dir_paths
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        self.server_close()


if __name__ == '__main__':
    with BaseServer([], ('', 8000), HTTPRequestHandler) as server:
        server.serve_forever()
