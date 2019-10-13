import hashlib, base64
from flask import Flask, request, make_response
from Crypto.Cipher import AES

app = Flask(__name__)
server_password = 'test_server'
server_secret_key = hashlib.md5(server_password.encode('utf-8'))

@app.route('/service')
def service():
    data = request.headers
    encrypted_authenticator = data['authenticator']
    service_ticket = data['service_ticket']

    decryption_obj = AES.new(server_secret_key.hexdigest().encode(), AES.MODE_CBC,
                             server_secret_key.hexdigest()[:16].encode())
    decrypted_service_ticket = decryption_obj.decrypt(base64.b64decode(service_ticket)).decode().strip()
    print(decrypted_service_ticket)
    sk2 = decrypted_service_ticket.split(' ')[-1]
    print(sk2)

    decryption_obj = AES.new(sk2, AES.MODE_CBC, sk2)
    authenticator = decryption_obj.decrypt(base64.b64decode(encrypted_authenticator)).decode().strip()[1:]
    print(authenticator)

    if (decrypted_service_ticket.split(' ')[0] != authenticator.split(' ')[0]) or (decrypted_service_ticket.split(' ')[1] != authenticator.split(' ')[1]):
        return make_response('Client not valid, dropping connection', 400)

    return make_response("Authentication Completed", 200)


if __name__ == '__main__':
    app.run(port=8081, debug=True)
