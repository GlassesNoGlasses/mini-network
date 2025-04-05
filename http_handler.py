
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
from secrets import choice
from string import ascii_uppercase, digits
from constants import BOUNDARY_LENGTH

class HTTPRequestHandler(BaseHTTPRequestHandler):

    def find_files(self, files: list[str], duplicates: bool = False, 
                   location: str | None = None) -> dict[str, list[str]]:
        ''' Finds specified files/dirs "files" in the server directory.

            @param files: list[str] - The files/dirs to find.
            @param duplicates: bool - (optional) Whether to allow duplicate file names in the response. 
            @param location: str - (optional) The location to search for the files.
            If empty, searches from user's current directory.
            :rtype: dict[str, list[str]]
            :return: last found file if duplicates is False, else returns all found files.
        '''
        print(f"Finding files: {files}")
        print(f"Allow duplicates: {duplicates}")

        if not files:
            return 

        dir_path = location if location else self.server.current_dir
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
    

    def _parse_file_data(self, file_data: bytes, boundary: str) -> dict[str, bytes]:
        ''' Parses the file data client POST/PUT requests.

            @param file_data: bytes - The file data to parse.
            @param boundary: str - The boundary string to split the file data.
            :rtype: dict[str, bytes]
            :return: The parsed file data `{f_name: {data: f_data, [headers...]}}`.
            :raises: ValueError if invalid file data found.
        '''

        file_data = file_data.split(b'--' + boundary.encode('utf-8'))[1:]
        parsed_files = {}

        for data in file_data:
            if data:
                file_metadata = data.split(b'\r\n')
                content_disposition = file_metadata[1].decode('utf-8').split(': ')[1].split('; ')
                file_name = content_disposition[2].split('=')[1].strip('"')
                parsed_files[file_name] = {}

                print(f"CONTENT DISPOSITION FOR: {file_name}", content_disposition)

                for i in range(3, len(content_disposition)):
                    header = content_disposition[i].split('=')
                    parsed_files[file_name][header[0]] = header[1].strip('"')

                file_content = data.split(b'\r\n\r\n')[1].strip(b'\r\n')
                parsed_files[file_name]['data'] = file_content

        return parsed_files
    

    def send_headers(self, headers: dict[str, str] | None) -> None:
        ''' Sends headers to the client. Defaults to sending Content-Type: text/html if no headers are provided.
        
            @param headers: dict[str, str] - The headers to send.
        '''

        if not headers:
            headers = {'Content-Type': 'text/plain'}
        
        for header, value in headers.items():
            self.send_header(header, value)
        self.end_headers()


    def _list_file_payload(self) -> tuple[str, bytes]:
        ''' Lists the files in the current directory and returns the payload.

            :rtype: tuple[str, bytes]
            :return: Returns a tuple containing (`res_boundary`, `res_boundary + payload + res_boundary`) 
            of the files in the current directory.
        '''

        current_dir = self.server.current_dir
        files = os.listdir(current_dir)
        boundary = '--' + ''.join(choice(ascii_uppercase + digits) for _ in range(BOUNDARY_LENGTH)) + '--'
        payload = boundary.encode('utf-8') + b'\r\n'

        for file in files:
            payload += f"{file}\r\n".encode('utf-8')
        
        payload += boundary.encode('utf-8')

        return (boundary, payload)


    def _change_client_dir(self, cd_dir: str) -> bool:
        ''' Changes client active directory. Returns True if directory change was successful.
            Raises ValueError if invalid path is given. Raises PermissionError if path is not allowed.

            @param path: cd_dir - The directory to change to.
            :raises: ValueError if invalid path is given.
            :raises: PermissionError if path change is not allowed.
            :rtype: bool
            :return: True if directory change is successful for user.
        '''

        if cd_dir == '.':
            return True
    
        current_dir = self.server.current_dir.split('/')
        
        # TODO: check user permissions to change to higher directories
        if cd_dir == '..':
            if len(current_dir) == 1:
                raise PermissionError("Invalid permissiosn to change to higher directory")
            elif len(current_dir) > 1:
                current_dir.pop()
        elif "\\" in cd_dir or "/" in cd_dir:
            raise ValueError(f"Invalid directory path {cd_dir}")
        elif cd_dir in os.listdir(self.server.current_dir):
            current_dir.append(cd_dir)
        else:
            raise ValueError(f"No existing directory {cd_dir} in {self.server.current_dir}")
        
        self.server.current_dir = '/'.join(current_dir)
        return True


    def do_GET(self):
        res_code: int = 200
        res_message: bytes | None = None

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
        self.send_headers()
        self.wfile.write(res_message)
        

    def do_POST(self):
        res_code: int = 200
        res_message: bytes | None = None
        res_headers = {}
        print(self.path)
        print("HEADERS: ", self.headers)

        try:
            # obtain the boundary, and content length from the headers
            boundary: str = self.headers['Boundary']
            content_length: int = int(self.headers['Content-Length'])
            print(f"Boundary: {boundary}")

            # TODO: work with data that are not files

            # handle POST files
            file_data = self._parse_file_data(self.rfile.read(content_length), boundary)

            for file_name, file_content in file_data.items():
                with open(f"{self.server.current_dir}/{file_name}", 'wb+') as f:
                    f.write(file_content['data'])
        
            res_boundary, res_message = self._list_file_payload()
            res_headers['Content-Type'] = 'multipart/list'
            res_headers['Boundary'] = res_boundary
        except KeyError:
            res_code = 400
            res_message = b"Could not find headers"

        self.send_response(res_code)
        self.send_headers(res_headers)
        self.wfile.write(res_message)
    

    def do_PUT(self):
        res_code: int = 200
        res_message: bytes | None = None
        res_headers = {}
        print(self.path)
        print("HEADERS: ", self.headers)

        try:
            # obtain the boundary, and content length from the headers
            boundary: str = self.headers['Boundary']
            content_length : int = int(self.headers['Content-Length'])
            print(f"Boundary: {boundary}")
    
            # handle PUT files
            file_data = self._parse_file_data(self.rfile.read(content_length), boundary)
            print("FILE DATA:", file_data)

            for file_name, file_content in file_data.items():
                with open(f"{self.server.current_dir}/{file_name}", 'wb+') as f:
                    f.write(file_content['data'])
                os.rename(f"{self.server.current_dir}/{file_name}", f"{self.server.current_dir}/{file_content['new_name']}")
            
            res_boundary, res_message = self._list_file_payload()
            res_headers['Content-Type'] = 'multipart/list'
            res_headers['Boundary'] = res_boundary
        
        except KeyError:
            res_code = 400
            res_message = b"Could not find headers"

        self.send_response(res_code)
        self.send_headers(res_headers)
        self.wfile.write(res_message)
    

    def do_DELETE(self):
        res_code: int = 200
        res_message: bytes | None = None
        res_headers = {}

        # DELETE request query handling
        headers = self.headers
        url = self.path
        query_components = parse_qs(urlparse(self.path).query)
        print(f"Headers: {headers}")
        print(f"URL: {url}")
        print(f"Query components: {query_components}")

        files_to_delete = query_components.get("files", '')
        print(f"Files to delete: {files_to_delete}")

        if not files_to_delete:
            res_code = 400
            res_message = b'Could not find files to delete'
        
        try:
            found_files = self.find_files(files_to_delete, duplicates=True)

            if not found_files:
                res_code = 404
                res_message = b'Files not found'
            else:
                for _, locations in found_files.items():
                    for file_path in locations:
                        if os.path.isdir(file_path):
                            rmtree(file_path)
                        else:
                            os.remove(file_path)

                res_boundary, res_message = self._list_file_payload()
                res_headers['Content-Type'] = 'multipart/list'
                res_headers['Boundary'] = res_boundary
        except Exception as e:
            print(f"Error deleting files: {e}")
            res_code = 500
            res_message = b'Error deleting files'


        self.send_response(res_code)
        self.send_headers(res_headers)
        self.wfile.write(res_message)


    def do_PATCH(self):
        res_code: int = 500
        res_message: bytes | None = None
        res_headers = {}

        # PATCH request query handling
        headers = self.headers
        url = self.path
        query_components = parse_qs(urlparse(self.path).query)
        print(f"Headers: {headers}")

        try:
            if headers['Content-Type'] == 'tls/init':
                encrypted_message = self.rfile.read(int(headers['Content-Length']))
                print(f"Encrypted message: {encrypted_message}")
                self.server.tls._establish_TLS(init_headers=headers, client_hello=encrypted_message)
                self.server._generate_client_session_id(headers['Client-Name'])
                res_message = self.server.tls.encrypt(b'sid=' + self.server.client_sessions[headers['Client-Name']])
                res_headers['Content-Type'] = 'tls/established'
                res_code = 200
            elif headers['Content-Type'] == 'traversal/*':
                print(f"URL: {url}")
                print(f"Query components: {query_components}")

                cd_dir = query_components.get("dir", [])

                if not cd_dir:
                    res_code = 400
                    res_message = f'Could not find {cd_dir} to change directory'.encode('utf-8')
                else:
                    self._change_client_dir(cd_dir[0])
                    res_boundary, payload = self._list_file_payload()
                    res_headers['Content-Type'] = 'multipart/list'
                    res_headers['Boundary'] = res_boundary
                    res_code = 200
                    res_message = payload
        except Exception as e:
            print(f"Error {e}")
            res_code = 500
            res_message = b'Error processing request'
            res_headers = {'Content-Type': 'text/plain'}

        self.send_response(res_code)
        self.send_headers(res_headers)
        self.wfile.write(res_message)

