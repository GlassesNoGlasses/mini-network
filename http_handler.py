
'''
File Name: request.py
Dependencies: BaseHTTPRequestHandler

Description:
This module contains the HTTPRequestHandler class which is a subclass of BaseHTTPRequestHandler.
It is used to handle GET, POST, PUT, and DELETE requests. 
The class is used in the BaseServer class in server.py.

'''

import os, fnmatch
from zipfile import ZipFile
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class HTTPRequestHandler(BaseHTTPRequestHandler):

    def find_files(self, files: list[str], duplicates: bool = False) -> dict[str, list[str]]:
        ''' Finds specified files "files" in the server directory. 
            @param files: list[str] - The files to find.
            @param duplicates: bool - (optional) Whether to allow duplicate file names in the response. 
            Returns last found file if duplicates is False, else returns all found files.
        '''
        print(f"Finding files: {files}")
        print(f"Allow duplicates: {duplicates}")

        if not files:
            return 

        root_dir = self.server._root
        found_files = {file_name.lower(): [] for file_name in files}

        for root, _, dir_files in os.walk(root_dir):
            for file in dir_files:
                if file.lower() in found_files:
                    if not duplicates:
                        found_files[file] = [os.path.join(root, file)]
                    else:
                        found_files[file].append(os.path.join(root, file))
        
        return found_files

    def do_GET(self):
        headers = self.headers
        url = self.path
        query_components = parse_qs(urlparse(self.path).query)
        print(f"Headers: {headers}")
        print(f"URL: {url}")
        print(f"Query components: {query_components}")
 
        requested_files = query_components.get("files", [])
        allow_duplicates = query_components.get("allow_duplicates", False)

        if allow_duplicates: 
            allow_duplicates = allow_duplicates[0].lower() == "true"

        found_files = self.find_files(requested_files, allow_duplicates)
        print(f"Found files: {found_files}")

        if not found_files:
            self.send_response(404)
            self.end_headers()
            return
        
        # TODO: modify headers and response based on found files
        self.send_response(200)
        self.send_header('Content-type','text/html') 
        self.end_headers()
        
        if len(found_files) == 1:
            file_name = list(found_files.keys())[0]
            file_location = found_files[file_name][0]
            with open(file_location, 'rb') as f:
                self.wfile.write(f.read())
        else:
            # Create a zip file containing the found files
            with ZipFile('GET_files.zip', 'a') as zipf:
                for locations in found_files.values():
                    for file_path in locations:
                        zipf.write(file_path)
            # Send the zip file
            with open('GET_files.zip', 'rb') as f:
                self.wfile.write(f.read())
            

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

