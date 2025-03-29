
'''
File Name: constants.py
Dependencies: None

Description:
This module contains the constants used in the mini-network package.
Constants are shared between the different modules in the package, and should
be updated to suit the specific use case of the package.

'''

from helper import ExtendedEnum

# Network Constants
PORT = 8080


# HTTP Constants
HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH'}

RESPONSE_CODES = {200, 201, 400, 404, 500}

CONTENT_TYPES = {'text/html', 'text/plain', 'multipart/form-data','file/*', 'file/.zip', 
                 'traversal/*', 'multipart/list', 'tls/init', 'tls/finish'}

BOUNDARY_LENGTH = 16


# TLS Constants
TLS_VERSION = 'TLSv1.3'


class CIPHER_SUITES(ExtendedEnum):
    ''' Enum class to represent the different cipher suites supported by the TLS class. 
        Custom cipher suites can be added here.
    '''

    AES128_GCM_SHA256 = 1
    AES256_GCM_SHA384 = 2
    CHACHA20_POLY1305_SHA256 = 3
    AES128_CCM_SHA256 = 4
