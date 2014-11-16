#!/usr/bin/python
# -*- coding: utf8 -*-

import os
import tempfile
import subprocess
import shutil
from flask import Flask, request

GPG_PATH = '/usr/bin/gpg'
GPG_HOME_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gpg-home')
GPG_FLAGS = ['-q', '--no-options', '--no-default-keyring',
             '--homedir', GPG_HOME_DIR]
GPG_KEY_FIELDS = [
    'type',
    'trust',
    'keylen',
    'algorithm',
    'keyid',
    'creationdate',
    'expirationdate',
    'serial',
    'ownertrust',
    'uid',
    '_',
]
GPG_KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')

app = Flask(__name__)


@app.route('/pks/add', methods=['POST'])
def submit_key():

    key_text = request.form['keytext']
    key_meta = {}

    with tempfile.NamedTemporaryFile() as temp:

        temp.write(key_text)
        temp.flush()

        try:
            gpg = subprocess.check_output(
                [GPG_PATH] + GPG_FLAGS + ["--with-colons", temp.name],
                stderr=open('/dev/null', 'w')
            )
            for line in gpg.splitlines():
                if line.startswith('pub:'):
                    key_meta = dict(zip(GPG_KEY_FIELDS, line.split(':')))

        except subprocess.CalledProcessError:
            return 'Invalid data', 400

        if not key_meta['keyid'] or not key_meta['uid']:
            return 'Invalid data', 400

        try:
            shutil.copy(temp.name,
                        os.path.join(GPG_KEY_DIR, key_meta['keyid']))
        except IOError:
            return 'Internal error', 500

    return 'Key successfully submitted', 200


@app.errorhandler(404)
def not_implemented(e):
    return 'This keyserver only accepts submissions', 404


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=11371)
