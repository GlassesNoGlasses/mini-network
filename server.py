
import os
import logging
from http_handler import HTTPRequestHandler
from http.server import HTTPServer

class BaseServer(HTTPServer):

    def __init__(self, dir_paths: list[str], server_address, RequestHandlerClass, bind_and_activate = True):
        try:
            invalid_paths = [path for path in dir_paths if not os.path.isdir(path)]

            if invalid_paths:
                raise FileNotFoundError(f"Invalid directory paths: {invalid_paths}")
            
        except FileNotFoundError:
            print(f"Invalid directory paths: {invalid_paths}. Would you like to create them? (y/n)")
            res = None

            while len(res = input().lower()) != 1:
                print("Invalid input. Please enter 'y' or 'n'")

            if res == 'y':
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
