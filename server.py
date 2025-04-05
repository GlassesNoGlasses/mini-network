
import os
import logging
from http_handler import HTTPRequestHandler
from http.server import HTTPServer
from constants import PORT, CIPHER_SUITES
from tls_config import Server_TLS

class BaseServer(HTTPServer):

    def __init__(self, root_dir: str, server_address: tuple, 
                 RequestHandlerClass: HTTPRequestHandler, bind_and_activate: bool = True,
                 tls_version: str = 'TLSv1.3', cipher_suite: CIPHER_SUITES = CIPHER_SUITES):
        '''
        Initializes the BaseServer class with the directory paths to serve.
        @param root_dir: str - The root directory to serve.
        @param server_address: tuple - The address (IP, PORT) of the server.
        @param RequestHandlerClass: HTTPRequestHandler - The class to handle requests.
        @param blocked_paths: list[str] - (optional) The paths to block from serving within root_dir.
        @param bind_and_activate: bool - (optional) Whether to bind and activate the server.
        '''

        print("[INFO]: Initializing BaseServer...")

        try:
            if not os.path.isdir(root_dir):
                raise FileNotFoundError(f"Invalid root directory: {root_dir}")
            
            self.current_dir = root_dir
            self.client_sessions = {}
            self.tls = Server_TLS(RequestHandlerClass, tls_version=tls_version, cipher_suite=cipher_suite)
            self.tls.server_address = server_address

            print(f"[INFO] Starting server at root dir: {root_dir}")
            print(f"[SERVER] WAITING FOR REQUESTS ON ADDRESS: {server_address}")

        except FileNotFoundError:
            option_message = f'''Invalid root directory: {root_dir}. Please select an option to proceed:
                           1. Create the directory.
                           2. Enter a new directory.
                           3. Exit
                           '''
            
            while True:
                option = input(option_message)[0]

                if option == '1':
                    os.makedirs(root_dir)
                    print(f"Created root direction: {root_dir}")
                    break
                elif option == '2':
                    root_dir = input("Enter a new root directory: ")

                    if os.path.isdir(root_dir):
                        break
                    else:
                        print("Could not find directory path")
                else:
                    print("Exiting...")
                    exit()
        finally:
            self._root = root_dir
            self.blocked_dirs = [".."]
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        

    def __enter__(self):
        return self
    
    def _generate_client_session_id(self, client_name: str) -> bytes:
        """ Generates a random session ID for the client.

            :returns: bytes - The generated session ID.
            :rtype: bytes
        """
        if not client_name:
            raise ValueError("Client name cannot be empty")
        
        if client_name in self.client_sessions:
            return self.client_sessions[client_name]
        return os.urandom(16)
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.server_close()


if __name__ == '__main__':
    with BaseServer("./test/server", ('', PORT), HTTPRequestHandler) as server:
        server.serve_forever()
