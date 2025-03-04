
'''
File Name: constants.py
Dependencies: None

Description:
This module contains the constants used in the mini-network package.
Constants are shared between the different modules in the package, and should
be updated to suit the specific use case of the package.

'''

# Network Constants
PORT = 8080


# HTTP Constants
HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE'}

RESPONSE_CODES = {200, 201, 400, 404, 500}

CONTENT_TYPES = {'application/json', 'application/xml', 'text/html', 'text/plain', 'multipart/form-data',
                 'image/jpeg', 'image/png', 'image/gif', 'file/*', 'file/.zip', 'traversal/*'}

CONTENT_TYPE_MAP = {
    '.txt': 'text/plain',
    '.html': 'text/html',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
}

BOUNDARY_LENGTH = 16