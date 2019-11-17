import base64
import hashlib
import json
from io import BytesIO
from typing import NamedTuple, Mapping, Any, List, Tuple
from zipfile import ZipFile

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from typeguard import typechecked

from Crypto.PublicKey import RSA


@typechecked
class ZHTIndexData(NamedTuple):
    meta: Mapping[str, str]
    key: str
    tags: List[str]
    previewFile: str
    files: Mapping[str, str]

    def encrypted_meta(self, public_key):
        return {
            "encryptedMeta": rsa_encrypt_str(json.dumps(self.meta), public_key),
            "encryptedKey": rsa_encrypt_str(self.key, public_key),
            "encryptedTags": [rsa_encrypt_str(t, public_key) for t in self.tags],
            "previewFile": self.previewFile,
            "files": list(self.files.keys())
        }

    def encrypted_files(self):
        for nm, content in self.files.items():
            yield nm, aes_encrypt_str(content, self.key)

    @classmethod
    def from_encrypted_data(cls,
                            private_key: str,
                            encryptedMeta: str,
                            encryptedKey: str,
                            encryptedTags: List[str],
                            previewFile: str,
                            encryptedFiles: Mapping[str, str]
                            ) -> 'ZHTIndexData':
        key = rsa_decrypt_str(encryptedKey, private_key)
        return ZHTIndexData(
            meta=json.loads(rsa_decrypt_str(encryptedMeta, private_key)),
            key=key,
            tags=[
                rsa_decrypt_str(t, private_key)
                for t in encryptedTags
            ],
            previewFile = previewFile,
            files={
                nm: aes_decrypt_str(content, key)
                for nm, content in encryptedFiles.items()
            }
        )



AES_IV = b'\0' * 16


def rsa_encrypt_str(s: str, public_key: str) -> str:
    public_key = RSA.import_key(public_key.encode('ascii'))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher_rsa.encrypt(s.encode('utf-8'))).decode('ascii')


def rsa_decrypt_str(e: str, private_key: str) -> str:
    rsa = RSA.import_key(private_key.encode('ascii'))
    cipher_rsa = PKCS1_OAEP.new(rsa)
    return cipher_rsa.decrypt(base64.b64decode(e.encode('ascii'))).decode('utf-8')


def aes_encrypt_str(s: str, key: str) -> str:
    bkey = base64.b64decode(key)
    aes = AES.new(bkey, AES.MODE_CBC, AES_IV)
    return base64.b64encode(aes.encrypt(pad(s.encode('utf-8'), 16))).decode('ascii')


def aes_decrypt_str(e: str, key: str) -> str:
    bkey = base64.b64decode(key)
    aes = AES.new(bkey, AES.MODE_CBC, AES_IV)
    return unpad(aes.decrypt(base64.b64decode(e.encode('utf-8'))), 16).decode('utf-8')


def data_by_index(index: int, tag_num: int, file_num: int) -> ZHTIndexData:
    meta = {
        "title": f"data_{index}"
    }
    key = base64.b64encode(hashlib.sha256(f"key_{index}".encode('utf-8')).digest()).decode('ascii')
    return ZHTIndexData(
        meta=meta,
        key=key,
        tags=[f"标签_{i}" for i in range(tag_num)],
        files={f"file_{i}": f"内容_{i}" for i in range(file_num)},
        previewFile='file_0'
    )


def data_to_zip(data: ZHTIndexData, key: str) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, 'w') as zipFile:
        with zipFile.open('index.json', 'w') as f:
            f.write(json.dumps(data.encrypted_meta(key)).encode('utf-8'))
        for fn, fd in data.encrypted_files():
            with zipFile.open(fn, 'w') as f:
                f.write(fd.encode('utf-8'))
    return buffer.getvalue()