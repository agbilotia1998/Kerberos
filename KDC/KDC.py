import hashlib, random, string, Padding, base64
from flask import Flask, request, make_response, jsonify, json
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
tgs_secret_key = ''

class Clients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(250))


class TGS(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(250))
    is_available = db.Column(db.Integer)


@app.route('/authenticating_server')
def authenticating_server():
    client_id = request.headers.get('id')
    print('Request from Client ID ' + str(client_id))
    client = Clients.query.filter_by(id=client_id).scalar()

    if not client:
        return make_response('Client not valid, dropping connection', 400)

    tgs = TGS.query.filter_by(is_available=1).scalar()

    if not tgs:
        return make_response('Client not valid, dropping connection', 400)

    client_secret_key = hashlib.md5(client.password.encode('utf-8'))
    print(client_secret_key)
    global tgs_secret_key
    tgs_secret_key = hashlib.md5(tgs.password.encode('utf-8'))

    sk1 = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    print("Session key " + sk1)
    encryption_obj = AES.new(client_secret_key.hexdigest().encode(), AES.MODE_CBC, client_secret_key.hexdigest()[:16].encode())
    # encrypted_sk1 = encryption_obj.encrypt(sk1)

    life_span = 1000
    tgt = "".join(str(client_id) + ' ' + str(request.remote_addr) + ' ' + str(life_span) + ' ' + str(datetime.now()) + ' ' + sk1)
    encryption_obj = AES.new(tgs_secret_key.hexdigest().encode(), AES.MODE_CBC, tgs_secret_key.hexdigest()[:16].encode())
    padded_tgt = Padding.appendPadding(tgt, AES.block_size, mode='CMS')
    encrypted_tgt = encryption_obj.encrypt(padded_tgt)

    response = {
        "sk1": sk1,
        "tgt": base64.b64encode(encrypted_tgt).decode()
    }
    encryption_obj = AES.new(client_secret_key.hexdigest().encode(), AES.MODE_CBC, client_secret_key.hexdigest()[:16].encode())
    padded_response = Padding.appendPadding(json.dumps(response), AES.block_size, mode='CMS')
    encrypted_response = encryption_obj.encrypt(padded_response)

    print(response)
    return make_response({'data': base64.b64encode(encrypted_response).decode()}, 200)

@app.route('/tgs')
def tgs():
    data = request.headers
    encrypted_authenticator = base64.b64decode(data.get('authenticator'))
    encrypted_tgt = base64.b64decode(data.get('tgt'))

    decryption_obj = AES.new(tgs_secret_key.hexdigest().encode(), AES.MODE_CBC, tgs_secret_key.hexdigest()[:16].encode())
    tgt = decryption_obj.decrypt(encrypted_tgt).decode()
    sk1 = tgt.split(' ')[-1]
    sk1 = sk1[:16]

    decryption_obj = AES.new(sk1, AES.MODE_CBC, sk1)
    authenticator = decryption_obj.decrypt(encrypted_authenticator).decode()
    if tgt.split[' '][0] != authenticator.split[' '][0] or tgt.split[' '][1] != authenticator.split[' '][1]:
        return make_response('Client not valid, dropping connection', 400)

    return make_response('Verified', 200)


if __name__ == '__main__':
    db.create_all()
    app.run(port=8080, debug=True)
