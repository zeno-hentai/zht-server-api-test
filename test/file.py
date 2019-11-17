from typing import Tuple

from lib.config import zht_config
from test.utils.api import ZHTSessionTest
from test.utils.file import data_by_index, data_to_zip, ZHTIndexData


class FileTest(ZHTSessionTest):
    token_title = 'test-title'
    token_header_name = 'ZHT-API-TOKEN'
    file_number = 10

    def setUp(self):
        super().setUp()
        self.register()
        self.token_id, self.token = self.create_api_token()

    def tearDown(self):
        self.delete_api_token(self.token_id)
        self.delete()
        super().tearDown()

    def create_api_token(self) -> Tuple[int, str]:
        res = self.session.post(zht_config.url('/api/api/token/create'), json={
            'title': self.token_title
        })
        data = self.json(res)
        return data['id'], data['token']

    def delete_api_token(self, token_id):
        res = self.session.delete(zht_config.url(f'/api/api/token/delete/{token_id}'))
        self.json(res)

    def test_api_token(self):
        res = self.session.get(zht_config.url('/api/api/token/query'))
        data = self.json(res)
        self.assertTrue(any(
            d['id'] == self.token_id and d['title'] == self.token_title
            for d in data
        ), "Token not found")

    def get_public_key(self):
        res = self.session.get(zht_config.url('/api/api/public-key'), headers={
            self.token_header_name: self.token
        })
        publicKey = self.json(res)
        self.assertEqual(self.publicKey, publicKey)
        return publicKey

    def get_paging(self, total):
        res = self.session.get(zht_config.url('/api/item/paging'), headers={
            self.token_header_name: self.token
        })
        data = self.json(res)
        self.assertEqual(total, data['total'])
        return data['total']

    def get_items(self, total, page_size):
        counter = 0
        for offset in range(0, total, page_size):
            res = self.session.get(zht_config.url(f'/api/item/query/{offset}/{page_size}'), headers={
                self.token_header_name: self.token
            })
            data = self.json(res)
            counter += len(data)
            yield from data
        self.assertEqual(total, counter)

    def get_file_list(self, item_id):
        res = self.session.get(zht_config.url(f'/api/file/list/{item_id}'))
        return self.json(res)

    def get_file_data(self, name):
        res = self.session.get(zht_config.url(f'/api/file/data/{name}'))
        self.assertEqual(200, res.status_code)
        return res.content.decode("utf-8")

    def get_item(self, dt):
        item_id = dt['id']
        encryptedKey = dt['encryptedKey']
        encryptedMeta = dt['encryptedMeta']
        encryptedTags = dt['tags']
        encryptedFiles = {
            nm: self.get_file_data(nm)
            for nm in self.get_file_list(item_id)
        }
        info = self.check_session()
        encryptedPrivateKey = info['encryptedPrivateKey']
        self.assertEqual(self.encryptedPrivateKey, encryptedPrivateKey)
        privateKey = self.decryptPrivateKey(encryptedPrivateKey).decode('ascii')
        return ZHTIndexData.from_encrypted_data(
            private_key=privateKey,
            encryptedKey=encryptedKey,
            encryptedMeta=encryptedMeta,
            encryptedTags=[t['encryptedTag'] for t in encryptedTags],
            encryptedFiles=encryptedFiles
        )

    def test_file_upload(self):
        public_key = self.get_public_key()
        items = [
            data_by_index(i, 10, 20)
            for i in range(self.file_number)
        ]
        for data in items:
            b = data_to_zip(data, public_key)
            res = self.session.post(zht_config.url("/api/api/upload"), data = b, headers = {
                self.token_header_name: self.token
            })
            self.json(res)
        total = self.get_paging(self.file_number)
        for orig, data in zip(items, self.get_items(total, 3)):
            item = self.get_item(data)
            self.assertEqual(orig.meta, item.meta)
            self.assertEqual(item.key, item.key)
            self.assertEqual(set(orig.tags), set(item.tags))
            self.assertEqual(set(orig.files.values()), set(item.files.values()))


