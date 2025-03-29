
'''
File Name: client.py
Dependencies: server

Description:
This module contains the Client class which is used to connect to a server.

Note:
User inputs should be sanitized incorperated before being used in the application.
Only BASIC sanitization is performed in this module.
'''

from tls_config import Client_TLS
from http_sender import BaseHTTPSender
from requests import Response
from constants import CONTENT_TYPES, RESPONSE_CODES, CIPHER_SUITES
from dotenv import load_dotenv

class Client():
    def __init__(self, sender: BaseHTTPSender, tls_version: str = 'TLSv1.3', cipher_suite: CIPHER_SUITES = CIPHER_SUITES):
        ''' Initializes the Client class with the specified HTTP sender object.
            Custom cipher suites should be updated in the CIPHER_SUITES constant in the `constants.py` module.
        
            :param sender: The HTTP sender object to use for sending requests.
            :type sender: http_sender
            :param tls_version: The version of TLS to use. Default is 'TLSv1.3'.
            :type tls_version: str
            :param cipher_suite: The cipher suite to use. Default is the CIPHER_SUITES constant.
            :type cipher_suite: set[str]
        ''' 
        self.request_sender = sender
        self.server_url = None

        self.tls = Client_TLS(sender, tls_version=tls_version, cipher_suite=cipher_suite)


    def connect(self, server_url: str) -> bool:
        ''' Connects to the server specified by `server_url`. Must be called before sending any requests.

            :param server_url: The URL of the server to connect to.
            :type server_url: str
            :returns: True if the connection was successful, False otherwise.
            :rtype: bool
        '''


        # TODO: implement DNS request to server
        self.server_url = server_url
        

    def initiate_TLS_handshake(self) -> bool:
        ''' Initiates the TLS 1.3 handshake with the server. 

            :returns: True if the handshake was successful, False otherwise.
            :rtype: bool
        '''

        # TODO: implement user auth details

        self.tls.INIT_TLS_Handshake(self.server_url)


    
    def parse_input(self, input_str: str) -> tuple[str, list[str]]:
        ''' Parses the user input to extract the method and files/folders to perform the method on. '''
        # input_str = input_str.strip()
        # input_str = input_str.split(" ")

        # method = input_str[0].upper()
        # files = input_str[1:]

        # return method, files


    def handle_successful_response(self, response: Response):
        ''' Handles a successful response from the server. 
            @param response: Response - The response from the server.
        '''
        print(f"Response status code: {response.status_code}")
        print(f"Response content type: {response.headers['Content-Type']}")
        print(f"Response content: {response.content}")
        
        match response.headers['Content-Type']:
            case 'multipart/list':
                boundary = response.headers['Boundary']
                print(f"Boundary: {boundary}")
                listed_files = response.content.split(boundary)[1]
                print(f"Listed files: {listed_files}")
            case _:
                print(f"Unknown content type: {response.headers['Content-Type']}")
        


    def handle_unsuccessful_response(self, response: Response):
        ''' Handles an unsuccessful response from the server. 
            @param response: Response - The response from the server.
        '''
        print(f"Response status code: {response.status_code}")


    def handle_response(self, response: Response | None):
        ''' Handles the response from the server.

            @param response: Response | None - The response from the server.
        '''

        if not response:
            print("No response received from the server.")
            return
        
        try:
            assert response.status_code in RESPONSE_CODES, f"Invalid response status code: {response.status_code}"
            assert response.headers['Content-Type'], f"Missing content type: {response.headers['Content-Type']}. Bad Response."
            assert response.headers['Content-Type'] in CONTENT_TYPES.values(), f"Invalid content type: {response.headers['Content-Type']}"

            if response.status_code in (200, 201):
                self.handle_successful_response(response)
            elif response.status_code in (400, 404, 500):
                print(f"An error occurred on the server: {response.status_code}")
            else:
                print(f"An unknown error occurred on the server: {response.status_code}")


        except AssertionError as e:
            print(f"An error occurred while handling the response: {e}")

        except Exception as e:
            print(f"An error occurred while handling the response: {e}")

        print(f"Response status code: {response.status_code}")


    def send_request(self, method: str, files: list[str], location: list[str] = [], 
                     duplicates: bool = False) -> Response | None:
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
    
        response = None

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
                case "PATCH":
                    response = self.request_sender.PATCH(files, location)
                case _:
                    raise ValueError(f"Invalid method: {method}")
            
            return response
        except ValueError as e:
            print(f"An error occurred while sending the request: {e}")
            return
        except Exception as e:
            print(f"An error occurred while sending the request: {e}")
            return
    