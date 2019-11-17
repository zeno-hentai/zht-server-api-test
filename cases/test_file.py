from typing import Tuple

from lib.config import zht_config
from utils.api import ZHTSessionTest
from utils.file import data_by_index, data_to_zip, ZHTIndexData, rsa_encrypt_str


class FileTest(ZHTSessionTest):
    token_title = 'cases-title'
    token_header_name = 'ZHT-API-TOKEN'
    file_number = 10
    remove_number = 4

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
        previewFile = dt['previewFile']
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
            previewFile = previewFile,
            encryptedTags=[t['encryptedTag'] for t in encryptedTags],
            encryptedFiles=encryptedFiles
        )

    def delete_item(self, item_id):
        res = self.session.delete(zht_config.url(f"/api/item/delete/{item_id}"))
        d = self.json(res)
        self.assertEqual(item_id, d['id'])

    def upload_file(self, data: ZHTIndexData, public_key: str):
        b = data_to_zip(data, public_key)
        res = self.session.post(zht_config.url("/api/api/upload"), data=b, headers={
            self.token_header_name: self.token
        })
        data = self.json(res)
        return data['id']

    def get_item_by_id(self, item_id):
        res = self.session.get(zht_config.url(f"/api/item/get/{item_id}"))
        dt = self.json(res)
        return self.get_item(dt)

    def add_tag(self, item_id, tag, public_key):
        res = self.session.post(zht_config.url(f"/api/item/tag/add"), json=dict(
            itemId=item_id,
            encryptedTag=rsa_encrypt_str(tag, public_key)
        ))
        dt = self.json(res)
        return dt['id']

    def delete_tag(self, tag_id):
        res = self.session.delete(zht_config.url(f"/api/item/tag/delete/{tag_id}"))
        self.json(res)

    def test_file_upload(self):
        public_key = self.get_public_key()
        items = [
            data_by_index(i, 10, 20)
            for i in range(self.file_number)
        ]
        for data in items:
            self.upload_file(data, public_key)
        total = self.get_paging(self.file_number)
        responses = list(self.get_items(total, 3))
        results = [
            self.get_item(d)
            for d in responses
        ]
        for orig, item in zip(items, results):
            self.assertEqual(orig.meta, item.meta)
            self.assertEqual(orig.key, item.key)
            self.assertEqual(orig.files.get(orig.previewFile), item.files.get(item.previewFile))
            self.assertEqual(set(orig.tags), set(item.tags))
            self.assertEqual(set(orig.files.values()), set(item.files.values()))

    def test_item(self):
        test_tag = 'shit'
        public_key = self.get_public_key()
        item = data_by_index(0, 10, 20)
        item_id = self.upload_file(item, public_key)
        self.get_paging(1)
        tag_id = self.add_tag(item_id, test_tag, public_key)
        item2 = self.get_item_by_id(item_id)
        self.assertTrue(test_tag in item2.tags)
        self.delete_tag(tag_id)
        item3 = self.get_item_by_id(item_id)
        self.assertFalse(test_tag in item3.tags)
        self.delete_item(item_id)
        self.get_paging(0)
