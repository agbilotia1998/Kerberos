import hashlib, Padding
import requests, base64
import json
from Crypto.Cipher import AES
from datetime import datetime


class Client:
    kdc_url = 'http://localhost:8080'
    server_url = 'http://localhost:8081'

    def __init__(self):
        self.get_client_parameters()
        self.compute_client_hash()

    def get_client_parameters(self):
        self.id = 1
        self.password = 'client_pass'
        self.address = '127.0.0.1'

    def compute_client_hash(self):
        self.secret_key = hashlib.md5(self.password.encode('utf-8'))
        print('Client Secret Key ' + str(self.secret_key))

    def request_kdc(self):
        headers = {'id': str(self.id)}
        response = requests.get(self.kdc_url + '/authenticating_server', headers=headers)
        if response.status_code == 200:
            data = json.loads(response.content)['data']
            data = base64.b64decode(data)
            decryption_obj = AES.new(self.secret_key.hexdigest().encode(), AES.MODE_CBC,
                                     self.secret_key.hexdigest()[:16].encode())
            decrypted_data = json.loads(str(decryption_obj.decrypt(data).decode()).strip()[:-(2)])
            print(decrypted_data)
            sk1 = decrypted_data["sk1"]
            tgt = decrypted_data["tgt"]
            print(sk1)
            print(tgt)
            authenticator = str(self.id) + ' ' + str(self.address) + ' ' + str(datetime.now())
            padded_authenticator = Padding.appendPadding(json.dumps(authenticator), AES.block_size, mode='CMS')
            encryption_obj = AES.new(sk1, AES.MODE_CBC, sk1)
            encrypted_authenticator = encryption_obj.encrypt(padded_authenticator)

            tgs_request_parameters = {
                'authenticator': base64.b64encode(encrypted_authenticator).decode(),
                'tgt': tgt
            }
            tgs_response = requests.get(url=self.kdc_url + '/tgs', headers=tgs_request_parameters)
            if tgs_response.status_code == 200:
                data = json.loads(tgs_response.content)['data']
                data = base64.b64decode(data)
                decryption_obj = AES.new(sk1, AES.MODE_CBC, sk1)
                decrypted_data = json.loads(str(decryption_obj.decrypt(data).decode()).strip()[:-(7)])
                print(decrypted_data)
                sk2 = decrypted_data["sk2"]
                service_ticket = decrypted_data["service_ticket"]
                print(sk2)
                print(service_ticket)

                server_authenticator = str(self.id) + ' ' + str(self.address) + ' ' + str(datetime.now())
                padded_server_authenticator = Padding.appendPadding(json.dumps(server_authenticator), AES.block_size, mode='CMS')
                encryption_obj = AES.new(sk2, AES.MODE_CBC, sk2)
                encrypted_server_authenticator = encryption_obj.encrypt(padded_server_authenticator)

                server_request_parameters = {
                    'authenticator': base64.b64encode(encrypted_server_authenticator).decode(),
                    'service_ticket': service_ticket
                }
                server_response = requests.get(url=self.server_url + '/service', headers=server_request_parameters)
                print(server_response)

            else:
                print(response.content)
        else:
            print(response.content)


if __name__ == '__main__':
    client = Client()
    client.request_kdc()
