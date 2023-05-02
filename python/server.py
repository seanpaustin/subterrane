#!/usr/bin/env python3

import base64
import logging
import sys
import traceback

from flask import Flask, request, session
from flask_socketio import SocketIO

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


app = Flask(__name__)
app.config['SECRET_KEY'] = "secret!"
socketio = SocketIO(app, logger=True, engineio_logger=True, cors_allowed_origins="*")


@socketio.event
def connect(auth):
    if not auth:
        logging.warning("connect failed: no authentication information provided")
        return False

    public_key = auth.get('public_key')
    hashed_salt = auth.get('hashed_salt')
    signature = auth.get('signature')

    if not public_key or not hashed_salt or not signature:
        logging.warning("connect failed: missing authentication details: public_key=%s, hashed_salt=%s, signature=%s",
                        public_key, hashed_salt, signature)
        return False

    logging.warning("connect successful: sid=%s, public_key=%s, hashed_salt=%s, signature=%s",
                    request.sid, public_key, hashed_salt, signature)

    try:
        decoded_signature = base64.b64decode(signature)

        verifier = serialization.load_pem_public_key(public_key.encode('utf8'))
        verifier.verify(
            decoded_signature,
            bytes(hashed_salt, 'utf8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception as e:
        logging.warning("connect unsuccessful: invalid credentials: %s", e)
        traceback.print_exc()
        return False

    session['public_key'] = public_key

    return True


@socketio.event
def disconnect():
    logging.info("client disconnected")


@socketio.event
def push(args):
    args['public_key'] = session['public_key']
    socketio.emit('peer_updated', args, skip_sid=request.sid)


@socketio.event
def query(args):
    args['public_key'] = session['public_key']
    socketio.emit('peer_queries', args, skip_sid=request.sid)


@socketio.event
def blab(args):
    args['public_key'] = session['public_key']
    socketio.emit('peer_blabs', args, skip_sid=request.sid)


if __name__ == '__main__':
    port = int(sys.argv[1])
    socketio.run(app, port=port, allow_unsafe_werkzeug=True)
