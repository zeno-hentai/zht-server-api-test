from unittest import TestCase
import uuid

import requests
from requests import Response

import hashlib
import base64
from lib.config import zht_config
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA


class ZHTSessionTest(TestCase):
    def setUp(self):
        self.username = f"username:{uuid.uuid4()}"
        self.password = f"password:{uuid.uuid4()}"
        rsa = RSA.generate(2048)
        self.__iv = b'0' * 16
        aes = AES.new(hashlib.sha256(self.password.encode('utf-8')).digest(), AES.MODE_CBC, self.__iv)
        self.publicKey = rsa.publickey().exportKey().decode('latin-1')
        self.__privateKey = rsa.exportKey()
        priKeyB = aes.encrypt(pad(self.__privateKey, 16))
        self.encryptedPrivateKey = base64.b64encode(priKeyB).decode('ascii')
        self.session = requests.session()

    def decryptPrivateKey(self, encryptedPrivateKey: str):
        aes = AES.new(hashlib.sha256(self.password.encode('utf-8')).digest(), AES.MODE_CBC, self.__iv)
        return unpad(aes.decrypt(base64.b64decode(encryptedPrivateKey)), 16)

    def checkPrivateKey(self, encryptedPrivateKey: str):
        privateKey = self.decryptPrivateKey(encryptedPrivateKey)
        self.assertEqual(self.__privateKey, privateKey)

    def test_encryptPrivateKey(self):
        self.checkPrivateKey(self.encryptedPrivateKey)

    def tearDown(self):
        self.session.close()

    def json(self, response: Response):
        self.assertEqual(200, response.status_code)
        resp = response.json()
        self.assertFalse("error" in resp, resp.get("error"))
        return resp.get('data')

    def register(self):
        res = self.session.post(zht_config.url("/api/auth/register"), json=dict(
            masterKey=zht_config.masterKey,
            username=self.username,
            password=self.password,
            publicKey=self.publicKey,
            encryptedPrivateKey=self.encryptedPrivateKey
        ))
        data = self.json(res)
        self.assertEqual(self.username, data['username'])
        return data

    def login(self):
        res = self.session.post(zht_config.url("/api/auth/login"), json=dict(
            username=self.username,
            password=self.password
        ))
        data = self.json(res)
        self.assertEqual(self.username, data['username'])
        return data

    def logout(self):
        res = self.session.delete(zht_config.url("/api/auth/logout"))
        return self.json(res)

    def delete(self):
        res = self.session.delete(zht_config.url("/api/auth/delete"))
        return self.json(res)

    def check_session(self):
        res = self.session.get(zht_config.url("/api/user/info"))
        return self.json(res)