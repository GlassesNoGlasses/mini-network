
'''
File Name: request.py
Dependencies: BaseHTTPRequestHandler

Description:
This module contains the HTTPRequestHandler class which is a subclass of BaseHTTPRequestHandler.
It is used to handle GET, POST, PUT, and DELETE requests. 
The class is used in the BaseServer class in server.py.

'''

import os, fnmatch
from shutil import rmtree
from zipfile import ZipFile
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class HTTPRequestHandler(BaseHTTPRequestHandler):

    def find_files(self, files: list[str], duplicates: bool = False, location: str | None = None) -> dict[str, list[str]]:
        ''' Finds specified files/dirs "files" in the server directory. 
            @param files: list[str] - The files/dirs to find.
            @param duplicates: bool - (optional) Whether to allow duplicate file names in the response. 
            @param location: str - (optional) The location to search for the files.
            If empty, searches from root server directory.
            Returns last found file if duplicates is False, else returns all found files.
        '''
        print(f"Finding files: {files}")
        print(f"Allow duplicates: {duplicates}")

        if not files:
            return 

        dir_path = location if location else self.server._root
        found_files = {file_name.lower(): [] for file_name in files}

        for root, dirs, dir_files in os.walk(dir_path):
            # TODO: refactor this if possible; same logic
            for file in dir_files:
                if file.lower() in found_files:
                    if not duplicates:
                        found_files[file] = [os.path.join(root, file)]
                    else:
                        found_files[file].append(os.path.join(root, file))
            for dir in dirs:
                if dir.lower() in found_files:
                    if not duplicates:
                        found_files[dir] = [os.path.join(root, dir)]
                    else:
                        found_files[dir].append(os.path.join(root, dir))
        
        return found_files
    

    def do_GET(self):
        res_code: int = 200
        res_message: bytes = b''

        # GET request query handling
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
            res_code = 404
            res_message = b'Files not found'
        else:
            if len(found_files.keys()) == 1:
                print("Found single file")
                file_name = list(found_files.keys())[0]
                file_location = found_files[file_name][0]
                with open(file_location, 'rb') as f:
                    res_message = f.read()
            else:
                # Create a zip file containing the found files
                with ZipFile('GET_files.zip', 'a') as zipf:
                    for locations in found_files.values():
                        for file_path in locations:
                            zipf.write(file_path)
                # Send the zip file
                with open('GET_files.zip', 'rb') as f:
                    res_message = f.read()
        
        # TODO: modify headers and response based on found files
        self.send_response(res_code)
        self.send_header('Content-type','text/html') 
        self.end_headers()
        self.wfile.write(res_message)
        


    def do_POST(self):
        res_code = 200
        res_message = None
        print(self.path)
        print("HEADERS: ", self.headers)

        try:
            # obtain the location, boundary, and content length from the headers
            location = self.headers['Location'] if 'Location' in self.headers and self.headers['Location'] else './test/server'
            boundary = self.headers['Content-Type'].split("=")[1]
            content_length = int(self.headers['Content-Length'])
            print(f"Location: {location}")
            print(f"Boundary: {boundary}")

            # TODO: work with data that are not files
            # handle the POST data
            post_data_files = self.rfile.read(content_length).split(b'--' + boundary.encode('utf-8'))[1:]
            print(f"POST data: {post_data_files}")

            for file_data in post_data_files:
                if file_data:
                    file_metadata = file_data.split(b'\r\n')
                    content_disposition = file_metadata[1].decode('utf-8')
                    file_name = content_disposition.split('filename=')[1].strip('"')
                    file_content = file_data.split(b'\r\n\r\n')[1].strip(b'\r\n')
                    with open(f"{location}/{file_name}", 'wb') as f:
                        f.write(file_content)
            
            res_message = "POST request successful"
        except KeyError:
            res_code = 400
            res_message = "Could not find headers"



        self.send_response(res_code)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(bytes(res_message, "utf8"))
    

    def do_PUT(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()


        message = "Hello, World! Here is a PUT response"
        self.wfile.write(bytes(message, "utf8"))
    

    def do_DELETE(self):
        res_code = 200
        res_message = ''

        # DELETE request query handling
        headers = self.headers
        url = self.path
        query_components = parse_qs(urlparse(self.path).query)
        print(f"Headers: {headers}")
        print(f"URL: {url}")
        print(f"Query components: {query_components}")

        files_to_delete = query_components.get("files", '')
        file_location = headers['Content-Location']
        print(f"Files to delete: {files_to_delete}")
        print(f"File location: {file_location}")

        if not file_location or not files_to_delete:
            res_code = 400
            res_message = 'Could not find files to delete'
        
        try:
            found_files = self.find_files(files_to_delete, duplicates=True, location=file_location)

            if not found_files:
                res_code = 404
                res_message = 'Files not found'
            else:
                for _, locations in found_files.items():
                    for file_path in locations:
                        if os.path.isdir(file_path):
                            rmtree(file_path)
                        else:
                            os.remove(file_path)

                file_names = ','.join(list(found_files.keys()))
                res_message = f'Files {file_names} deleted successfully'
        except Exception as e:
            print(f"Error deleting files: {e}")
            res_code = 500
            res_message = 'Error deleting files'


        self.send_response(res_code)
        self.send_header('Content-type','text/html')
        self.end_headers()

        self.wfile.write(bytes(res_message, "utf8"))

