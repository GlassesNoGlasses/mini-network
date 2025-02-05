
import requests
from constants import PORT, HTTP_METHODS

class BaseHTTPSender():
    def __init__(self, url=f"http://localhost:{PORT}"):
        self.url = url

    def send_request(self, method: str, data):
        method = method.split()[0].upper()
        response = None

        try:
            assert method in HTTP_METHODS
            response = requests.request(method, self.url, data=data)
        except AssertionError:
            print(f"Invalid HTTP method: {method}")
            return
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while sending the request: {e}")
            return
        
        return response.json()




