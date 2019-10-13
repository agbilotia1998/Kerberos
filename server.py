from flask import Flask, request, make_response

app = Flask(__name__)


@app.route('/service')
def service():
    data = request.headers
    authenticator = data['authenticator']
    service_ticket = data['service_ticket']

    print(authenticator)
    print(service_ticket)

    return make_response("Authentication Completed", 200)


if __name__ == '__main__':
    app.run(port=8081, debug=True)
