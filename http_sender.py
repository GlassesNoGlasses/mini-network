
'''
File Name: http_sender.py
Dependencies: requests, tls, constants

Description:
This module contains the BaseHTTPSender class which is used to send HTTP requests to a server.
'''

import requests
import os
from string import ascii_uppercase, digits
from secrets import choice
from constants import PORT, HTTP_METHODS, BOUNDARY_LENGTH

class BaseHTTPSender():
    def __init__(self, url=f"http://localhost:{PORT}"):
        ''' Initializes the BaseHTTPSender class with the URL of the server to send requests to. 
        '''

        self.url = url

    
    def GET(self, files: list[str], duplicates: bool = False) -> requests.Response | None:
        ''' Sends a GET request to the server. 

            @param files: list[str] - The files/folders to retrieve.
            @param location: list[str] - (optional) The location to retrieve specified files.
            If empty, searches entire server.
            @param duplicates: bool - (optional) Whether to retrieve duplicate files from multiple locations.
            :returns: The response from the server.
            :rtype: requests.Response | None
        '''

        if not files:
            print("No files specified to retrieve in GET request.")
            return

        params = {"files": files, "allow_duplicates": duplicates}

        return self._send_request("GET", params=params)
    

    def POST(self, files: list[str]) -> requests.Response | None:
        ''' Sends a POST request to the server. POST requests uploads files `files` to the server at user's current path.

            @param files: list[str] - The files to upload.
            :rtype: requests.Response | None
            :returns: The response from the server.
        '''

        if not files:
            print("No files specified to upload in POST request.")
            return
        
        # TODO: Find some way to handle relative paths or create absolute paths
        # for file in files:
        #     if not os.path.exists(file):
        #         print(f"File {file} does not exist.")
        #         return
            # elif not os.path.isfile(file):
            #     print(f"File {file} is not a valid file.")
            #     return
        
        return self._send_request("POST", files=files)
    

    def PUT(self, files: dict[str, str]) -> requests.Response | None:
        ''' Sends a PUT request to the server. PUT requests update/replace files on the server at user's current path.
            @param files: dict[str, str] - The files/folders to update in the form `{path_to_file: new_file_name}`.
            If no new file name is specified, the file is created/replaced with the same name.
            :returns: The response from the server.
            :rtype: requests.Response | None
        '''

        if not files:
            print("No files specified to update in PUT request.")
            return
        
        # for file in files.keys():
        #     if not self._validate_path(file) or os.path.isdir(files):
        #         return
    
        parsed_files = {self._parse_file_by_path(file)[0]: new_name for file, new_name in files.items()}
        disposition_headers = {file: {'new_name': new_name if new_name else file} for file, new_name in parsed_files.items()}

        return self._send_request("PUT", files=list(files.keys()), disp_headers=disposition_headers)
    

    def DELETE(self, files: list[str]) -> requests.Response | None:
        ''' Sends a DELETE request to the server. Removes files/dirs from the server.
            @param files: list[str] - The files/folders to delete.
            :returns: The response from the server.
            :rtype: requests.Response | None
        '''

        if not files:
            print("Missing files in DELETE request.")
            return
        
        params = {'files': ';'.join(files)}

        return self._send_request("DELETE", params=params)


    def PATCH(self, dir: str) -> requests.Response | None:
        ''' Sends a PATCH request to the server. Changes directory of current user path.
            @param dir: str - The new directory to change to.
            :returns: The response from the server.
            :rtype: requests.Response | None
        '''

        if not dir:
            print("No directory specified in PATCH request.")
            return
        
        custom_headers = {'Content-Type': 'traversal/*'}
        
        return self._send_request("PATCH", params={'dir': dir}, headers=custom_headers)
    

    def TLS_INIT(self, mode: bytes , message: bytes, c_suite: str) -> requests.Response | None:
        ''' Initializes TLS handshake connection with the server.

            @param mode: bytes - The mode to use for the cipher suite, encrypted by sha256 with the nonce.
            @param message: bytes - The message to send to the server.
            @param nonce: bytes - The nonce of client to send to the server.
            :returns: The response from the server.
            :rtype: requests.Response | None
        '''

        custom_headers = {'Content-Type': 'tls/init'}
        custom_headers['Content-Length'] = str(len(message))
        custom_headers['Mode'] = mode
        custom_headers['Cipher-Suite'] = c_suite
        
        return self._send_request("PATCH", headers=custom_headers, data=message)
    

    def _validate_path(self, path: str) -> bool:
        ''' Validates the path to ensure it is a valid file or directory.

            Backwards traversal is not allowed by clients and should be done by the server via GET requests.

            @param path: str - The path to validate.
            :rtype: bool
            :return: True if the path is valid, False otherwise.
        '''

        path_content = path.split('/')

        for i in range(len(path_content)):
            # check for backwards traversal or invalid characters
            if path_content[i] == ".." or '/' in path_content[i] or '\\' in path_content[i]:
                print(f"Backwards traversal is not allowed in client.")
                return False

        if not os.path.exists(path):
            print(f"Path {path} does not exist.")
            return False
        elif not os.path.isfile(path) and not os.path.isdir(path):
            print(f"Path {path} is not a valid file or directory.")
            return False
    
        return True


    def _parse_file_by_path(self, file_path: str) -> tuple[str, str]:
        ''' Parses the file path to extract the file name and file extension.
            @param file: str - The file path to parse.
            :return: A tuple containing the (file name, file extension).
            :rtype: tuple[str, str]
        '''

        file_name = os.path.basename(file_path)
        file_extension = os.path.splitext(file_path)[1]

        return file_name, file_extension
    

    def _craft_file_payload(self, files: list[str], boundary: str, 
                            disposition_headers: dict[str, dict[str, str]] | None = None) -> bytearray | None:
        ''' Crafts the file data to be sent in the request.
            @param files: list[str] - The files to send.
            @param boundary: str - The boundary string to separate the files.
            @param disposition_headers: dict[str, dict[str, str]] - (optional) Additional content disposition
            headers for each file. Maps {`file_name`: {`header_name`: `header_value`}}. `file_name` must be in `files`.
            :rtype: bytearray | None
            :return: The file payload to send in the request body. Returns None if no files are specified.
            :rtype: bytearray | None
        '''

        # Payload Format: 
        #   --boundary\r\nConent-Disposition: form-data; name="file1"; filename="file1_name"; {disposition_headers}\r\n\r\nfile1_data\r\n
        #   --boundary\r\nConent-Disposition: form-data; name="file2"; filename="file2_name"; {disposition_headers}\r\n\r\nfile2_data\r\n

        if not files:
            print("[ERROR] No files specified to craft payload.")
            return

        payload = b''
        separator = b'\r\n'
        boundary = f'--{boundary}'.encode(encoding='utf-8') + separator
        content_disposition = b'Content-Disposition: form-data; name="file"; filename="'


        # TODO: add encoding
        for file in files:
            f_name, _ = self._parse_file_by_path(file)
            payload += boundary
            payload += content_disposition
            payload += f_name.encode(encoding='utf-8')

            # add additional disposition headers if specified
            if disposition_headers and f_name in disposition_headers:
                for header, value in disposition_headers[f_name].items():
                    payload += f'"; {header}="{value}'.encode(encoding='utf-8')

            payload += b'"' + separator + separator
            with open(file, 'rb') as f:
                payload += f.read()
            payload += separator

        return payload
    

    def _send_request(self, method: str, params: dict | None = None, 
                      headers: dict | None = None, files: list[str] | None = None,
                      disp_headers: dict[str, dict[str, str]] | None = None,
                      data: str | bytes | None = None) -> requests.Response | None:
        ''' Main method to send HTTP requests to the server.

            @param method: str - The HTTP method to use.
            @param params: dict - (optional) The parameters to send with the request.
            @param headers: dict - (optional) The custom headers to send with the request.
            @param files: list[str] - (optional) The file paths of files to send in the request.
            @param disp_headers: dict[str, dict[str, str]] - (optional) Additional content disposition
            headers for each file. Maps {`file_name`: {`header_name`: `header_value`}}. `file_name` must be in `files`.
            @param data: str | bytes - (optional) The data to send in the request body.
            :returns: The response from the server.
            :rtype: requests.Response | None
        '''
        method = method.split()[0].upper()
        response = None

        try:
            assert method in HTTP_METHODS
            data = data if data else None
            custom_headers = headers if headers else {}
            custom_headers["User-Agent"] = "User101"

            # file handling
            if files:
                boundary = ''.join(choice(ascii_uppercase + digits) for _ in range(BOUNDARY_LENGTH))
                custom_headers["Content-Type"] = f"multipart/files"
                custom_headers["Boundary"] = boundary

                data = self._craft_file_payload(files, boundary, disposition_headers=disp_headers)  

            response = requests.request(method, self.url, params=params, data=data, headers=custom_headers)

        except AssertionError:
            print(f"Invalid HTTP method: {method}")
            # TODO: prompt user for another request
            return 
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while sending the request: {e}")
            return
        
        return response




