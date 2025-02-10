
'''
File Name: client.py
Dependencies: server

Description:
This module contains the Client class which is used to connect to a server.

Note:
User inputs should be sanitized incorperated before being used in the application.
Only BASIC sanitization is performed in this module.
'''

from http_sender import BaseHTTPSender

class Client():
    def __init__(self, sender: BaseHTTPSender):
        self.request_sender = sender
        self.server_url = None


    def connect(self, server_url: str):
        ''' Attempts to conenct to the server whilst providing auth details. '''
        print(f"Connecting to the server: {server_url}")

        # TODO: implement code to authenticate user


    def send_request(self, method: str, files: list[str], location: list[str] = [], duplicates: bool = False):
        '''
        Sends a request to the server. Protocols are defined in the HTTPSender class.
        
        @param method: str - The method to perform on the server.
        @param files: list[str] - The files/folders for specified method.
        @param location: list[str] - (optional) The location/directory in server to perform the method.
        @param duplicates: bool - (optional) Whether to allow duplicates in the response.
        '''

        # REFINE: handle case where server URL is not specified
        if not self.server_url:
            print("No server URL specified.")
            return

        try:
            match method.upper():
                case "GET":
                    response = self.request_sender.GET(files, location, duplicates)
                case "POST":
                    response = self.request_sender.POST(files, location)
                case "PUT":
                    response = self.request_sender.PUT(files, location)
                case "DELETE":
                    response = self.request_sender.DELETE(files, location)
                case _:
                    print(f"Invalid method: {method}")
                    return
        except Exception as e:
            print(f"An error occurred while sending the request: {e}")
            return
