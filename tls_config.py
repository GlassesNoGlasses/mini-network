
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
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class EncryptionDetails():
    def __init__(self, mode: str, **kwargs):
        ''' Initializes the EncryptionDetails class with the mode. Mode should be one of the supported cipher suites.

            :param mode: The encryption mode to use. Must be one of the supported cipher suites.
            :type mode: str
            :param kwargs: Additional arguments to pass to the cipher suite initialization.
            :type kwargs: dict
        '''
        self.mode = mode
        self.details = {}

        match mode:
            case 'AES128_GCM_SHA256':
                self._init_AES128_GCM_SHA256(gen=kwargs.get('generator', 3), key_size=kwargs.get('key_size', 2048))
            case _:
                pass

    def get_mode(self) -> str:
        ''' Returns the encryption mode. 

            :returns: The encryption mode.
            :rtype: str
        '''
        assert self.mode, "No encryption mode found. TLS not established."
        return self.mode

    
    def _init_AES128_GCM_SHA256(self, gen: int = 3, key_size: int = 2048) -> None:
        ''' Initializes the AES128-GCM-SHA256 cipher suite. Stores the details in `self.details` dictionary.

            :param gen: The generator to use. Must be between 2 and 5 (inclusive).
            :type gen: int
            :param key_size: The key size to use. Must be 2048, 3072, or 4096.
            :type key_size: int
            :raises AssertionError: If the generator or key size is invalid.
        '''

        assert 2 <= gen <= 5, "Invalid generator. Must be 2 or 3."
        assert key_size in [2048, 3072, 4096], "Invalid key size. Must be 2048, 3072, or 4096."

        self.details['generator'] = gen
        self.details['key_size'] = key_size
        self.details['dh_params'] = dh.generate_parameters(generator=gen, key_size=key_size)
        self.details['private_key'] = self.details['dh_params'].generate_private_key()
        self.details['public_key'] = self.details['private_key'].public_key()
        return



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

        if self.mode == CIPHER_SUITES.AES128_GCM_SHA256:
            cipher = AES.new(key=self.key, mode=AES.MODE_GCM)
            server_nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return server_nonce + tag + ciphertext
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

    
    def _parse_AES_128_GCM_SHA256(self, client_hello: bytes) -> None:
        ''' Parses the client hello message from the client. 

            :param client_hello: The encrypted in AES GCM Mode client hello message.
            :type
            client_hello: bytes
        '''

        # parse the client hello message
        c_nonce = client_hello[:16]
        tag = client_hello[16:32]
        ciphertext = client_hello[32:]
        print(f"Ciphertext: {ciphertext}")
        print(f"Tag: {tag}")
        print(f"Nonce: {c_nonce}")
        cipher = AES.new(key=self.key, mode=AES.MODE_GCM, nonce=c_nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Plaintext: {plaintext}")

        # retrieve the generator, key size, and public key from the plaintext
        raw_generator, raw_key_size, pub_key = plaintext.split(b'&')
        generator = int.from_bytes(raw_generator.split(b'=')[1], 'big')
        key_size = int.from_bytes(raw_key_size.split(b'=')[1], 'big')
        pub_key = serialization.load_pem_public_key(pub_key)
        print(f"Generator: {generator}")
        print(f"Key size: {key_size}")
        print(f"Public key: {pub_key}")

        # generate the shared key
        self.encryption_details = EncryptionDetails(mode='AES128_GCM_SHA256', kwargs={'generator': generator, 'key_size': key_size})
        self.encryption_details.details['shared_key'] = self.encryption_details.details['private_key'].exchange(pub_key)
        key = HKDF(
            algorithm=sha256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.encryption_details.details['shared_key'])

        self._set_encryption_details(key=key, mode=CIPHER_SUITES.AES128_GCM_SHA256)


    

    def _establish_TLS(self, init_headers: dict[str, str], client_hello: bytes) -> tuple[bytes, bytes, bytes] | None:
        ''' Parses the client hello message from the client. 

            :returns: The ciphertext, tag, and nonce.
            :rtype: tuple[bytes, bytes, bytes] | None
        '''

        key = os.getenv('SHARED_PRIVATE_KEY').encode()
        assert key, "No shared private key found between server and client."
        key = key[:16]
        print('KEY: ', key)

        
        mode = None
        encrypted_mode = init_headers['Mode']
        c_nonce = client_hello[:16]
        
        for suite in self.cipher_suite.list_names():
            if sha256(suite.encode() + c_nonce).hexdigest() == encrypted_mode:
                mode = suite
                break

        assert mode, "No cipher suite found in the client hello message."

        match mode:
            case 'AES128_GCM_SHA256':
                self._parse_AES_128_GCM_SHA256(init_headers, client_hello)
            case _:
                print(f"Unsupported cipher suite: {mode}.")
                return None
        
        assert self.key, "No encryption key found. TLS not established."
        assert self.mode, "No encryption mode found. TLS not established."
        
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
    def _create_client_hello(self, mode: str) -> tuple[bytes, bytes, bytes]:
        ''' Initiates the TLS 1.3 handshake with the server. 

            :param mode: The mode to use for the cipher suite. Default is `AES128-GCM-SHA256`.
            :returns: The ciphertext, tag, and nonce.
            :rtype: tuple[bytes, bytes, bytes]
        '''

        print("Initiating TLS 1.3 handshake with the server.")
        assert mode in self.cipher_suite.list_names(), f"Unsupported cipher suite: {mode}. Supported cipher suites are: {self.cipher_suite.list_names()}"

        # TODO: implement `mode` variable; inlcudes modification of key length
        key = os.getenv('SHARED_PRIVATE_KEY').encode()
        assert key, "No shared private key found between server and client."
        key = key[:16]
        print('KEY: ', key)

        self.encryption_details = EncryptionDetails(mode=mode)
        msg = b'g=' + self.encryption_details.details['generator'].to_bytes(2, 'big') 
        msg += b'&p=' + self.encryption_details.details['key_size'].to_bytes(2, 'big')
        msg += b'&pub_key=' + self.encryption_details.details['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        cipher = AES.new(key=key, mode=AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(msg)
    
        return ciphertext, tag, cipher.nonce
    

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
            ciphertext, tag, nonce = self._create_client_hello(mode=mode)
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


