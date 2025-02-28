
'''
File Name: http_sender.py
Dependencies: requests, tls, constants

Description:
This module contains the BaseHTTPSender class which is used to send HTTP requests to a server.
'''

import requests
import tls
import os
from string import ascii_uppercase, digits
from secrets import choice
from constants import PORT, HTTP_METHODS, BOUNDARY_LENGTH, CONTENT_TYPE_MAP

class BaseHTTPSender():
    def __init__(self, url=f"http://localhost:{PORT}", tls: tls.TLS | None = None, cipher_suite=None):
        ''' Initializes the BaseHTTPSender class with the URL of the server to send requests to. 
            Optionally, the TLS and cipher suite can be specified.
        '''
        self.url = url
        self.tls = tls

    
    def GET(self, files: list[str], duplicates: bool = False):
        ''' Sends a GET request to the server. 
            @param files: list[str] - The files/folders to retrieve.
            @param location: list[str] - (optional) The location to retrieve specified files.
            If empty, searches entire server.
            @param duplicates: bool - (optional) Whether to retrieve duplicate files from multiple locations.
        '''

        if not files:
            print("No files specified to retrieve in GET request.")
            return

        params = {"files": files, "allow_duplicates": duplicates}

        return self._send_request("GET", params=params)
    

    def POST(self, files: list[str], locations: list[str] = [], replacement: bool = True):
        ''' Sends a POST request to the server.
            @param files: list[str] - The files to upload.
            @param locations: list[str] - (optional) The location(s) to upload specified files.
            If empty, uploads to root directory. Defaults to empty.
            @param replacement: bool - (optional) Whether to replace existing files with the same name.
            Defaults to True.
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
        
        data = {'locations': locations, 'replace': replacement}

        return self._send_request("POST", data=data , files=files)
    

    def PUT(self, files: list[str]):
        ''' Sends a PUT request to the server.
            @param files: list[str] - The files/folders to update.
            @param location: list[str] - (optional) The location to update specified files.
            If empty, updates files in root directory.
        '''

        if not files:
            print("No files specified to update in PUT request.")
            return

        return self._send_request("PUT", files=files)
    

    def DELETE(self, files: list[str]):
        ''' Sends a DELETE request to the server.
            @param files: list[str] - The files/folders to delete.
            @param location: list[str] - (optional) The location to delete specified files.
            If empty, deletes files in root directory.
        '''

        if not files:
            print("No files specified to delete in DELETE request.")
            return

        return self._send_request("DELETE", files=files)
    

    def _parse_file_by_path(self, file: str) -> tuple[str, str]:
        ''' Parses the file path to extract the file name and file extension.
            @param file: str - The file path to parse.
            @return tuple[str, str] - A tuple containing the file name and file extension.
        '''
        file_name = os.path.basename(file)
        file_extension = os.path.splitext(file)[1]

        return file_name, file_extension
    

    def _send_request(self, method: str, params: dict | None = None, data: dict | None = None, files: list[str] = []):
        ''' Main method to send HTTP requests to the server. Encrypts with specified TLS version and cipher suite
            if specified.
        '''
        method = method.split()[0].upper()
        response = None

        try:
            assert method in HTTP_METHODS
            custom_headers = {}
            sending_files = None


            # file handling
            if files:
                sending_files = {}

                # print(files)
                if len(files) == 1:
                    f_name, f_ext = self._parse_file_by_path(files[0])
                    custom_headers["Content-Type"] = f"{CONTENT_TYPE_MAP.get(f_ext, 'application/octet-stream')}"
                    sending_files[f_name] = open(files[0], 'rb')
                else:
                    boundary = ''.join(choice(ascii_uppercase + digits) for _ in range(BOUNDARY_LENGTH))
                    custom_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                
                    for file in files:
                        f_name, f_ext = self._parse_file_by_path(file)
                        sending_files[f_name] = (f_name, open(file, 'rb'), f"{CONTENT_TYPE_MAP.get(f_ext, 'application/octet-stream')}")

            response = requests.request(method, self.url, params=params, data=data, files=sending_files)

            # close any open files
            if len(sending_files) == 1:
                list(sending_files.values())[0].close()
            elif len(sending_files) > 1:
                for fd in sending_files.values():
                    fd[1].close()

        except AssertionError:
            print(f"Invalid HTTP method: {method}")
            return
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while sending the request: {e}")
            return
        
        return response




