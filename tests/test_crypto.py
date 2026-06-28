import sys, unittest
sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

import webtoken


class TestCryptoPrimitives(unittest.TestCase):

    def test_generate_localhost_cert(self):
        ''' The native Rust X.509 builder generates valid PEM strings '''

        cert_pem, key_pem = webtoken.generate_localhost_cert()
        
        # Verify basic PEM structure and type
        self.assertIsInstance(cert_pem, str)
        self.assertIsInstance(key_pem, str)
        
        self.assertTrue(cert_pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(cert_pem.strip().endswith("-----END CERTIFICATE-----"))
        
        self.assertTrue(key_pem.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(key_pem.strip().endswith("-----END PRIVATE KEY-----"))
        
        # The generated certificate should be reasonably large (usually ~600-800 chars)
        self.assertGreater(len(cert_pem), 500)
        self.assertGreater(len(key_pem), 100)


    def test_generate_key_pairs(self):
        ''' Rust natively generates RSA, ECDSA, and EdDSA keys '''
        
        # Test RSA
        priv_rsa, pub_rsa = webtoken.generate_key_pair("RS256", 2048)
        self.assertIn(b"-----BEGIN PRIVATE KEY-----", priv_rsa)
        self.assertIn(b"-----BEGIN PUBLIC KEY-----", pub_rsa)
        
        # Test ECDSA
        priv_ec, pub_ec = webtoken.generate_key_pair("ES256")
        self.assertIn(b"-----BEGIN PRIVATE KEY-----", priv_ec)
        self.assertIn(b"-----BEGIN PUBLIC KEY-----", pub_ec)
        
        # Test Ed25519
        priv_ed, pub_ed = webtoken.generate_key_pair("EdDSA")
        self.assertIn(b"-----BEGIN PRIVATE KEY-----", priv_ed)
        self.assertIn(b"-----BEGIN PUBLIC KEY-----", pub_ed)


    def test_sign_and_verify_ed25519(self):
        ''' Native signing and verification pipeline works '''

        priv, pub = webtoken.generate_key_pair("EdDSA")
        message = b"The quick brown fox jumps over the lazy dog"
        
        # Sign using the properly exported _py function
        signature = webtoken.sign_py("EdDSA", priv, message)
        self.assertEqual(len(signature), 64) # Ed25519 signatures are exactly 64 bytes
        
        # Verify (Should silently succeed)
        webtoken.verify_py("EdDSA", pub, message, signature)
        
        # Verify Failure (Should throw PyValueError)
        with self.assertRaises(Exception):
            webtoken.verify_py("EdDSA", pub, b"Altered message", signature)


    def test_aes_gcm_256_encryption(self):
        ''' Authenticated Encryption with Associated Data (AEAD) works '''

        key = webtoken.random_bytes(32)
        plaintext = b"Highly confidential banking data"
        aad = b"Transaction ID: 999"
        
        # Encrypt
        ciphertext = webtoken.encrypt_aes_256_gcm(key, plaintext, aad=aad)
        
        # Ciphertext contains Nonce (12) + Plaintext + Tag (16)
        self.assertEqual(len(ciphertext), 12 + len(plaintext) + 16)
        
        # Decrypt
        decrypted = webtoken.decrypt_aes_256_gcm(key, ciphertext, aad=aad)
        self.assertEqual(decrypted, plaintext)
        
        # AAD Tampering should fail decryption
        with self.assertRaises(Exception):
            webtoken.decrypt_aes_256_gcm(key, ciphertext, aad=b"Transaction ID: 000")


    def test_pkce_generation(self):
        ''' Cryptographically secure random strings for OAuth2 PKCE '''

        verifier, challenge = webtoken.generate_pkce_pair()
        
        # PKCE strings are Base64Url unpadded, usually 43 chars for 32 bytes
        self.assertEqual(len(verifier), 43)
        self.assertEqual(len(challenge), 43)
        self.assertNotEqual(verifier, challenge)


    def test_x25519_key_agreement(self):
        ''' Static Diffie-Hellman Key Exchange computes matching secrets '''
        
        priv_a = webtoken.random_bytes(32)
        priv_b = webtoken.random_bytes(32)
        
        pub_a = webtoken.x25519_public_from_private(priv_a)
        pub_b = webtoken.x25519_public_from_private(priv_b)
        
        secret_a = webtoken.x25519_derive(priv_a, pub_b)
        secret_b = webtoken.x25519_derive(priv_b, pub_a)
        
        self.assertEqual(secret_a, secret_b)
        self.assertEqual(len(secret_a), 32)


if __name__ == '__main__':
    unittest.main()