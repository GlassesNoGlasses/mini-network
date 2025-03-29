
'''
File Name: tls.py
Dependencies: None

Description:
This module contains the TLS class which is used to encrypt data using a specified TLS version and cipher suite.
'''

import os
from http_sender import BaseHTTPSender
from http_handler import HTTPRequestHandler
from constants import CIPHER_SUITES
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv

class TLS():
    def __init__(self, tls_version: str = 'TLSv1.3', cipher_suite: CIPHER_SUITES = CIPHER_SUITES):
        ''' Initializes the TLS class with the specified TLS version and cipher suite.
            Custom cipher suites should be updated in the CIPHER_SUITES constant in the `constants.py` module.
        
            :param tls_version: The version of TLS to use. Default is 'TLSv1.3'.
            :type tls_version: str
            :param cipher_suite: The cipher suite to use. Default is the CIPHER_SUITES constant.
            :type cipher_suite: CIPHER_SUITES
        '''

        self.tls_version = tls_version
        self.cipher_suite = cipher_suite

    
    def _load_env(self) -> bool:
        ''' Loads the environment variables from the .env file.

            :returns: True if the environment variables were loaded successfully, False otherwise.
            :rtype: bool
        '''

        if not load_dotenv('./keys.env'):
            print("[ERROR]: Could not load .env file. Please ensure that the file and data exists.")
            return False
        
        assert os.getenv('SHARED_PRIVATE_KEY'), "No shared private key found between server and client."
        # TODO: handle key lengths

        return True


    def _set_encryption_details(self, key: bytes, mode: CIPHER_SUITES) -> None:
        ''' Sets the encryption key to use for encryption and decryption.

            :param key: The encryption key to use.
            :type key: bytes
        '''
        self.key = key 
        self.mode = mode
    

    def encrypt(self, data: bytes) -> bytes:
        ''' Encrypts the specified data using the encryption key.

            :param data: The data to encrypt.
            :type data: bytes
            :return: The encrypted data.
            :rtype: bytes
            :raises AssertionError: If no encryption key is found.
        '''

        assert self.mode, "No encryption mode found. TLS not established."
        assert self.key, "No encryption key found. TLS not established."

        pass


    def decrypt(self, data: bytes) -> bytes:
        ''' Decrypts the specified data using the encryption key.

            :param data: The data to decrypt.
            :type data: bytes
            :return: The decrypted data.
            :rtype: bytes
            :raises AssertionError: If no encryption key is found.
        '''

        assert self.mode, "No encryption mode found. TLS not established."
        assert self.key, "No encryption key found. TLS not established."

        pass


class Server_TLS(TLS):
    ''' The Server_TLS class is used to accept the TLS handshake from the client. '''
    def __init__(self, handler: HTTPRequestHandler, tls_version: str = 'TLSv1.3', cipher_suite: CIPHER_SUITES = CIPHER_SUITES):
        ''' Initializes the Server_TLS class with the specified TLS version and cipher suite.
            Custom cipher suites should be updated in the CIPHER_SUITES constant in the `constants.py`
            module.

            :param handler: The HTTP request handler to use for handling requests.
            :type handler: HTTPRequestHandler
            :param tls_version: The version of TLS to use. Default is 'TLSv1.3'.
            :type tls_version: str
            :param cipher_suite: The cipher suite to use. Default is the CIPHER_SUITES constant.
            :type cipher_suite: set[str]
        '''
        super().__init__(tls_version, cipher_suite)
        super()._load_env()
        self.handler = handler

    
    def _decrypt_client_hello(self, client_hello: bytes) -> tuple[bytes, bytes, bytes] | None:
        ''' Decrypts the client hello message from the client. 

            :returns: The ciphertext, tag, and nonce.
            :rtype: tuple[bytes, bytes, bytes] | None
        '''
    

    def _establish_TLS(self, init_headers: dict[str, str], client_hello: bytes) -> tuple[bytes, bytes, bytes] | None:
        ''' Parses the client hello message from the client. 

            :returns: The ciphertext, tag, and nonce.
            :rtype: tuple[bytes, bytes, bytes] | None
        '''

        key = os.getenv('SHARED_PRIVATE_KEY').encode()
        assert key, "No shared private key found between server and client."
        key = key[:16]
        print('KEY: ', key)

        print("Parsing client hello message.")
        c_nonce = client_hello[:16]
        tag = client_hello[16:32]
        ciphertext = client_hello[32:]
        print(f"Ciphertext: {ciphertext}")
        print(f"Tag: {tag}")
        print(f"Nonce: {c_nonce}")
        
        mode = None
        encrypted_mode = init_headers['Mode']
        
        for suite in self.cipher_suite.list_names():
            if sha256(suite.encode() + c_nonce).hexdigest() == encrypted_mode:
                mode = suite
                break

        assert mode, "No cipher suite found in the client hello message."

        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=c_nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Plaintext: {plaintext}")

        print("Client hello message parsed successfully.")



class Client_TLS(TLS):
    ''' The Client_TLS class is used to initiate the TLS handshake with the server. '''
    def __init__(self, sender: BaseHTTPSender, tls_version: str = 'TLSv1.3', cipher_suite: CIPHER_SUITES = CIPHER_SUITES):
        ''' Initializes the Client_TLS class with the specified TLS version and cipher suite.
            Custom cipher suites should be updated in the CIPHER_SUITES constant in the `constants.py`
            module.

            :param sender: The HTTP sender object to use for sending requests.
            :type sender: BaseHTTPSender
            :param tls_version: The version of TLS to use. Default is 'TLSv1.3'.
            :type tls_version: str
            :param cipher_suite: The cipher suite to use. Default is the CIPHER_SUITES constant.
            :type cipher_suite: CIPHER_SUITES
        '''
        super().__init__(tls_version, cipher_suite)
        super()._load_env()
        self.sender = sender

    # TODO: implement different cipher suites 
    def _create_client_hello(self, mode: str) -> tuple[bytes, bytes, bytes, bytes]:
        ''' Initiates the TLS 1.3 handshake with the server. 

            :param mode: The mode to use for the cipher suite. Default is `AES128-GCM-SHA256`.
            :returns: The ciphertext, tag, nonce, and client random.
            :rtype: tuple[bytes, bytes, bytes]
        '''

        print("Initiating TLS 1.3 handshake with the server.")

        # TODO: implement `mode` variable; inlcudes modification of key length
        key = os.getenv('SHARED_PRIVATE_KEY').encode()
        assert key, "No shared private key found between server and client."
        key = key[:16]
        print('KEY: ', key)

        client_random = get_random_bytes(16)
        msg = b'rdm=' + client_random
        nonce = get_random_bytes(16)

        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(msg)
    
        return ciphertext, tag, nonce, client_random
    

    def INIT_TLS_Handshake(self, server_url: str) -> bool:
        ''' Attempts to conenct to the server whilst providing auth details. 

            :param server_url: The URL of the server to connect to.
            :type server_url: str
            :return: True if the connection was successful, False otherwise.
            :rtype: bool
        '''
        print(f"Connecting to the server: {server_url}")

        # TODO: implement user choice of cipher suite

        if not server_url:
            print("No server URL specified.")
            return
        
        try:
            mode = 'AES128_GCM_SHA256'
            ciphertext, tag, nonce, rdm = self._create_client_hello(mode=mode)
            c_suite = f'{self.tls_version};{";".join(self.cipher_suite.list_names())}'
            print(f"Ciphertext: {ciphertext}")
            print(f"Tag: {tag}")
            print(f"Nonce: {nonce}")
            response = self.sender.TLS_INIT(mode=sha256(mode.encode() + nonce).hexdigest(), 
                                            message=nonce + tag + ciphertext, c_suite=c_suite)

            if not response or response.status_code != 200:
                print("Connection failed. Please check the server URL.")
                return False
        except AssertionError as e:
            print(e)
            return
    
        
        print("Connection successful.")
        return True



