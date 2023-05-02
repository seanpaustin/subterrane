#!/usr/bin/env python3

import socketio


class PeerState:
    def __init__(self, public_key):
        self.public_key = public_key
        self.branches = {}

    def update(self, relay_url, service, update_args):
        logging.warning("peer update from %s: %s", relay_url, json.dumps(update_args))

        if relay_url in self.branches:
            branch = self.branches[relay_url]
        else:
            branch = {}
            self.branches[relay_url] = branch

        if service not in branch:
            branch[service] = {}

        branch[service].update(update_args)
        logging.warning("updated peer state from %s for %s as %s: %s",
                        relay_url, service, self.public_key, json.dumps(branch[service]))


peer_states = {}


class Connection:
    def __init__(self, url, my_public_key, my_state):
        self.url = url
        self.my_public_key = my_public_key
        self.my_state = my_state
        self.client = socketio.Client()
        self.client.on('connect', self.on_connect)
        self.client.on('disconnect', self.on_disconnect)
        self.client.on('peer_updated', self.on_peer_updated)
        self.client.on('peer_queries', self.on_peer_queries)
        self.client.on('peer_blabs', self.on_peer_blabs)

    @staticmethod
    def on_connect():
        logging.warning("connect successful")

    @staticmethod
    def on_disconnect():
        logging.warning("server disconnected")

    def on_peer_updated(self, args):
        logging.warning("peer updated: %s", json.dumps(args))
        public_key = args['public_key']
        service = args['service']

        # TODO verify signature

        if public_key == self.my_public_key:
            self.my_state.update("local", service, args)
        else:
            if public_key not in peer_states:
                logging.warning("first time seeing peer: %s", public_key)
                peer_states[public_key] = PeerState(public_key)
            peer_states[public_key].update(self.url, service, args)

    def on_peer_queries(self, args):
        logging.warning("peer queried: %s", json.dumps(args))
        public_key = args['public_key']
        service = args['service']

        known = None
        if public_key == self.my_public_key:
            known = self.my_state.branches['local'].get(service)
        elif public_key in peer_states:
            peer_state = peer_states[public_key]
            if peer_state and self.url in peer_state.branches:
                known = peer_state.branches[self.url].get(service)
        if known:
            self.blab(**known)

    def on_peer_blabs(self, args):
        logging.warning("peer blabs: %s", json.dumps(args))
        public_key = args['public_key']
        service = args['service']

        # TODO verify signature

        if public_key == self.my_public_key and service not in (self.my_state.branches.get('local') or {}):
            self.my_state.update("local", service, args)
        else:
            if public_key not in peer_states:
                logging.warning("first time seeing peer: %s", public_key)
                peer_states[public_key] = PeerState(public_key)

            # simple merge logic as a stand-in
            peer_states[public_key].update(self.url, service, args)

    def connect(self, auth):
        logging.warning("connecting: %s", self.url)
        self.client.connect(self.url, auth=auth)

    def push(self, **kwargs):
        self.client.emit('push', kwargs)

    def query(self, **kwargs):
        self.client.emit('query', kwargs)

    def blab(self, **kwargs):
        self.client.emit('blab', kwargs)

    def is_connected(self):
        return self.client.connected


if __name__ == '__main__':
    import base64
    import hashlib
    import json
    import logging
    import random
    import string
    import sys
    import time

    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    private_key_file = sys.argv[1]
    public_key_file = sys.argv[2]
    handle = sys.argv[3]
    client_urls = sys.argv[4:]

    with open(private_key_file, 'rb') as opened:
        signer = serialization.load_pem_private_key(opened.read(), password=None)

    with open(public_key_file, 'rb') as opened:
        public_key_data = opened.read()

    hashed_salt = hashlib.sha256((''.join(random.choices(string.ascii_letters, k=128))).encode('utf8')).hexdigest()

    signature = signer.sign(
        bytes(hashed_salt, 'utf8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    main_public_key = public_key_data.decode('utf8')
    main_state = PeerState(main_public_key)

    connections = {}
    for client_url in client_urls:
        connections[client_url] = Connection(client_url, main_public_key, main_state)

    main_auth = {
        'public_key': main_public_key,
        'hashed_salt': hashed_salt,
        'signature': base64.b64encode(signature).decode('utf8')
    }
    logging.warning("auth: %s", json.dumps(main_auth))

    for _, connection in connections.items():
        connection.connect(auth=main_auth)

    time.sleep(1)  # give a chance for all connections to be established

    if handle == "query":
        demographics_query = {'service': "demographic", 'selector': main_public_key}
        for _, connection in connections.items():
            connection.query(**demographics_query)
    else:
        handle_update = {'service': "demographic", 'handle': handle}
        main_state.update("local", "demographic", handle_update)
        for _, connection in connections.items():
            connection.push(**handle_update)

    while any([connection.is_connected for connection in connections.values()]):
        time.sleep(1)
    logging.warning("all connections closed, shutting down")
