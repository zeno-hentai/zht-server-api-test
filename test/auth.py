from test.utils.api import ZHTSessionTest


class TestAuth(ZHTSessionTest):
    def test_auth(self):
        self.assertFalse(self.check_session())
        self.register()
        self.assertTrue(self.check_session())
        self.logout()
        self.assertFalse(self.check_session())
        self.login()
        self.assertTrue(self.check_session())
        self.delete()
        self.assertFalse(self.check_session())

    def test_user_info(self):
        self.register()
        info = self.check_session()
        self.assertTrue(info, "Not Logged in")
        self.assertTrue(self.username, info['username'])
        self.assertTrue(self.encryptedPrivateKey, info['encryptedPrivateKey'])
        self.checkPrivateKey(info['encryptedPrivateKey'])
        self.assertTrue(self.publicKey, info['publicKey'])
        self.delete()

