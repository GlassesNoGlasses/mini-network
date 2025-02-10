
'''
File Name: http_sender.py
Dependencies: requests, tls, constants

Description:
This module contains the BaseHTTPSender class which is used to send HTTP requests to a server.
'''

import requests
import tls
from constants import PORT, HTTP_METHODS

class BaseHTTPSender():
    def __init__(self, url=f"http://localhost:{PORT}", tls: tls.TLS | None = None, cipher_suite=None):
        ''' Initializes the BaseHTTPSender class with the URL of the server to send requests to. 
            Optionally, the TLS and cipher suite can be specified.
        '''
        self.url = url
        self.tls = tls


    def GET(self, files: list[str], location: list[str] = [], duplicates: bool = False):
        ''' Sends a GET request to the server. 
            @param files: list[str] - The files/folders to retrieve.
            @param location: list[str] - (optional) The location to retrieve specified files.
            If empty, searches entire server.
            @param duplicates: bool - (optional) Whether to retrieve duplicate files from multiple locations.
        '''

        if not files:
            print("No files specified to retrieve in GET request.")
            return

        params = {"locations": location, "allow_duplicates": duplicates}

        return self.send_request("GET", params=params)
    

    def POST(self, files: list[str], location: list[str] = []):
        ''' Sends a POST request to the server.
            @param files: list[str] - The files/folders to upload.
            @param location: list[str] - (optional) The location to upload specified files.
            If empty, uploads to root directory.
        '''

        if not files:
            print("No files specified to upload in POST request.")
            return

        data = {"files": files, "location": location}

        return self.send_request("POST", data=data)
    

    def PUT(self, files: list[str], location: list[str] = []):
        ''' Sends a PUT request to the server.
            @param files: list[str] - The files/folders to update.
            @param location: list[str] - (optional) The location to update specified files.
            If empty, updates files in root directory.
        '''

        if not files:
            print("No files specified to update in PUT request.")
            return

        data = {"files": files, "location": location}

        return self.send_request("PUT", data=data)
    

    def DELETE(self, files: list[str], location: list[str] = []):
        ''' Sends a DELETE request to the server.
            @param files: list[str] - The files/folders to delete.
            @param location: list[str] - (optional) The location to delete specified files.
            If empty, deletes files in root directory.
        '''

        if not files:
            print("No files specified to delete in DELETE request.")
            return

        data = {"files": files, "location": location}

        return self.send_request("DELETE", data=data)
    

    def send_request(self, method: str, params: dict | None = None, data: dict | None = None):
        ''' Main method to send HTTP requests to the server. Encrypts with specified TLS version and cipher suite
            if specified.
        '''
        method = method.split()[0].upper()
        response = None

        try:
            assert method in HTTP_METHODS
            response = requests.request(method, self.url, params=params, data=data)
        except AssertionError:
            print(f"Invalid HTTP method: {method}")
            return
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while sending the request: {e}")
            return
        
        return response




