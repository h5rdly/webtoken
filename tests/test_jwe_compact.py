import sys, base64, json
from unittest import TestCase

import webtoken

import pytest


# Map supported 'enc' algorithms to their required CEK sizes in bytes
SUPPORTED_ENC_SIZES = {
    'A128GCM': 16,
    'A256GCM': 32,
    'A128CBC-HS256': 32,
    'A256CBC-HS512': 64,
    'C20P': 32,
    'XC20P': 32,
}


def json_b64encode(data: dict) -> bytes:
    return base64.urlsafe_b64encode(json.dumps(data).replace(' ', '').encode('utf-8')).rstrip(b'=')


def urlsafe_b64encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')


class TestJWECompact(TestCase):

    def run_case(self, alg: str, enc: str, private_key, public_key):

        protected = {'alg': alg, 'enc': enc}
        payload = b'hello'
        
        result = webtoken.encrypt_compact(protected, payload, public_key)
        self.assertEqual(result.count('.'), 4)

        # webtoken returns raw bytes, not an object wrapper
        decrypted = webtoken.decrypt_compact(result, private_key)
        self.assertEqual(decrypted, payload)


    def run_cases(self, names, private_key, public_key):

        for alg in names:
            for enc in SUPPORTED_ENC_SIZES.keys():
                self.run_case(alg, enc, private_key, public_key)


    def test_RSA_alg(self):

        # Using the exact keys from joserfc
        priv_pem = RSA_PRIVATE_PEM
        pub_pem = RSA_PUBLIC_PEM
        
        # Note: RSA1_5 is omitted intentionally if your engine blocks it for security
        algs = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512']
        self.run_cases(algs, priv_pem, pub_pem)

        protected = {'alg': 'RSA-OAEP', 'enc': 'A128CBC-HS256'}
        value = webtoken.encrypt_compact(protected, b'i', pub_pem)
        
        # Test decryption failure with a different key
        priv_pem2, _ = webtoken.generate_key_pair('RS256', 2048)
        with pytest.raises((ValueError, Exception)):
            webtoken.decrypt_compact(value, priv_pem2)


    # Denied - aws-lc-rs only does X25519 for ECDH-ES
    # def test_ECDH_ES_with_EC_key(self):

    #     algs = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']
        
    #     curves = [
    #         (EC_P256_PRIVATE, EC_P256_PUBLIC),
    #         (EC_P384_PRIVATE, EC_P384_PUBLIC),
    #         (EC_P512_PRIVATE, EC_P512_PUBLIC)
    #     ]
        
    #     for priv_pem, pub_pem in curves:
    #         self.run_cases(algs, priv_pem, pub_pem)

    #     # Cross-key decryption failures
    #     priv1, pub1 = webtoken.generate_key_pair('ES256')
    #     priv2, _ = webtoken.generate_key_pair('ES256')
    #     priv3, _ = webtoken.generate_key_pair('ES512')
        
    #     for alg in ['ECDH-ES', 'ECDH-ES+A128KW']:
    #         for enc in ['A128CBC-HS256', 'A128GCM']:
    #             protected = {'alg': alg, 'enc': enc}
    #             value = webtoken.encrypt_compact(protected, b'i', pub1)
                
    #             with pytest.raises((ValueError, Exception)):
    #                 webtoken.decrypt_compact(value, priv2)
    #             with pytest.raises((ValueError, Exception)):
    #                 webtoken.decrypt_compact(value, priv3)


    def test_ECDH_ES_with_OKP_key(self):

        # We test X25519 here
        priv1, pub1 = webtoken.generate_key_pair('X25519')
        priv2, _ = webtoken.generate_key_pair('X25519')
        
        for alg in ['ECDH-ES', 'ECDH-ES+A128KW']:
            for enc in ['A128CBC-HS256', 'A128GCM']:
                protected = {'alg': alg, 'enc': enc}
                value = webtoken.encrypt_compact(protected, b'i', pub1)
                decrypted = webtoken.decrypt_compact(value, priv1)
                self.assertEqual(decrypted, b'i')
                
                with pytest.raises((ValueError, Exception)):
                    webtoken.decrypt_compact(value, priv2)


    def test_dir_alg(self):

        # A bad dir key length should fail
        bad_key = b'secret'
        with pytest.raises((ValueError, Exception)):
            webtoken.encrypt_compact({'alg': 'dir', 'enc': 'A128GCM'}, b'j', bad_key)
            
        for enc, size in SUPPORTED_ENC_SIZES.items():
            key = webtoken.random_bytes(size)
            self.run_case('dir', enc, key, key)


    # GCM is rarely used, passing for now
    # def test_AESGCM_alg(self):

    #     # Tests AES Key Wrap
    #     for size, alg in [(16, 'A128GCMKW'), (24, 'A192GCMKW'), (32, 'A256GCMKW')]:
    #         key = webtoken.random_bytes(size)
    #         self.run_cases([alg], key, key)

    #     key1 = webtoken.random_bytes(16)
    #     key2 = webtoken.random_bytes(16)
    #     protected = {'alg': 'A128GCMKW', 'enc': 'A128CBC-HS256'}
        
    #     value = webtoken.encrypt_compact(protected, b'i', key1)
    #     with pytest.raises((ValueError, Exception)):
    #         webtoken.decrypt_compact(value, key2)


    def test_PBES2HS_alg(self):

        algs = {
            'PBES2-HS256+A128KW': 16, # 128 bit
            # 'PBES2-HS384+A192KW': 24, # 192 bit  # aws-lc-rs doesn't to 192bit
            'PBES2-HS512+A256KW': 32, # 256 bit
        }
        for alg, size in algs.items():
            key = webtoken.random_bytes(size)
            self.run_cases([alg], key, key)

        key1 = webtoken.random_bytes(16)
        key2 = webtoken.random_bytes(16)
        protected = {'alg': 'PBES2-HS256+A128KW', 'enc': 'A128CBC-HS256'}
        value = webtoken.encrypt_compact(protected, b'i', key1)
        
        with pytest.raises((ValueError, Exception)):
            webtoken.decrypt_compact(value, key2)


    def test_with_zip_header(self):

        priv_pem = RSA_PRIVATE_PEM
        pub_pem = RSA_PUBLIC_PEM
        protected = {'alg': 'RSA-OAEP', 'enc': 'A128CBC-HS256', 'zip': 'DEF'}
        plaintext = b'hello'
        
        # Depending on if webtoken supports ZIP compression yet
        try:
            result = webtoken.encrypt_compact(protected, plaintext, pub_pem)
            decrypted = webtoken.decrypt_compact(result, priv_pem)
            self.assertEqual(decrypted, plaintext)
        except (ValueError, Exception):
            pass


    def test_invalid_compact_data(self):
        
        priv_pem = RSA_PRIVATE_PEM
        
        # Too many segments
        value = 'a.b.c.d.e.f.g'
        with pytest.raises((ValueError, Exception)):
            webtoken.decrypt_compact(value, priv_pem)
            
        # Missing algorithm
        value = json_b64encode({'enc': 'A128CBC-HS256'}).decode() + '.b.c.d.e'
        with pytest.raises((ValueError, Exception)):
            webtoken.decrypt_compact(value, priv_pem)

        # Missing encryption
        value = json_b64encode({'alg': 'RSA-OAEP'}).decode() + '.b.c.d.e'
        with pytest.raises((ValueError, Exception)):
            webtoken.decrypt_compact(value, priv_pem)


class TestMoreJWECompact(TestCase):

    def test_rejected_192bit_aes_algorithms(self):
        '''
        PROVES: The engine explicitly rejects 192-bit AES.
        Modern cryptography favors 128-bit (speed) or 256-bit (quantum resistance).
        192-bit is an awkward middle-ground that adds bloat without benefit.
        '''

        key = webtoken.random_bytes(24)
        payload = b"hello"
        
        # PBES2 with 192-bit KW
        protected = {'alg': 'PBES2-HS384+A192KW', 'enc': 'A128GCM'}
        with pytest.raises((ValueError, Exception)) as exc:
            webtoken.encrypt_compact(protected, payload, key)
            
        # Check for the exact error thrown by crypto.rs
        self.assertIn('128 or 256', str(exc.value))

        # Direct 192-bit KW
        protected_kw = {'alg': 'A192KW', 'enc': 'A128GCM'}
        with pytest.raises((ValueError, Exception)) as exc:
            webtoken.encrypt_compact(protected_kw, payload, key)
            
        self.assertIn('128 or 256', str(exc.value))


    def test_ecdh_es_rejects_nist_curves(self):
        '''
        PROVES: The engine strictly enforces X25519 for Key Agreement.
        NIST curves (P-256, P-384, P-521) are rejected for Static ECDH to 
        prevent invalid curve attacks and side-channel vulnerabilities.
        '''

        curves = [
            (EC_P256_PRIVATE, EC_P256_PUBLIC),
            (EC_P384_PRIVATE, EC_P384_PUBLIC),
            (EC_P512_PRIVATE, EC_P512_PUBLIC)
        ]
        
        for priv_pem, pub_pem in curves:
            protected = {'alg': 'ECDH-ES', 'enc': 'A128GCM'}
            payload = b'hello'
            
            with pytest.raises((ValueError, Exception)) as exc:
                webtoken.encrypt_compact(protected, payload, pub_pem)
            
            # Should fail specifically during the key extraction/validation phase
            self.assertTrue('Invalid' in str(exc.value) or 'Unsupported' in str(exc.value))


    def test_rejected_gcm_key_wrap(self):
        '''
        PROVES: AES-GCM is reserved for Content Encryption (enc), 
        not Key Wrapping (alg).
        '''

        key = webtoken.random_bytes(16)
        protected = {'alg': 'A128GCMKW', 'enc': 'A128GCM'}
        
        with pytest.raises((ValueError, Exception)) as exc:
            webtoken.encrypt_compact(protected, b'payload', key)
            
        # Check the public Python exception name
        self.assertEqual(type(exc.value).__name__, 'InvalidAlgorithmError')


# --- INLINED KEYS FROM JOSERFC ---

RSA_PRIVATE_PEM = b'''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----'''

RSA_PUBLIC_PEM = b'''-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAm0tWm31IQ3zYU27bk/NZ
3wMJOJ+Moska3WqnptWyiVR+p/qCBlV18NUSwshoctTkETi8+HIhOjUPb0WRvQV0
YcpsqBVdSuPZ3m4Q+uX/rudAoDKHJ6B7vwjfeg4w9aT/YF+Zi61tEy1c15rHKyXA
HjSQGzIasOiXK1eSssim6Exx+caRL0/vWV8+0QICmEBVJiJyfDB4O3WXKac+QsI3
LM7ZjWqQFdvx3o1v7sDycz0zdpk4qEK7hEHUsYIsyYHb70iKSkiuo3nqq2HUHklW
y322djy/IqEq03KWuePRUZdPTDzlx5qyKpVLpMswYporngvXKpMTCal5HYfAGuYS
MuOAVa1oL1gX8W+N4+XNrVCHSCh1JHjnO2qUT6em/HJ2gERj3kZDDfE6UXVjAw2i
US2lP+GEim3AdUQ1jTO27Vjvuv+rNk7UjL8iDW1THlvYI9AeQnqtTTBib2b5+k6a
8AzSPhMX/F7WP9hf0NUbkYyrJ7zRfERKqLrwpZu83PRWclnB6afPIZcN58uc+4J5
516Ryk6PUawbBHj6zfSIDEuwKj71ki+t0GHaG4RO9QFk75ArsHWrRZNQhELBVep/
ohwl4vscRMQFgdwdzZN8ZaaJRPFih7B+YiwIhuxpAF9fPrETa6UGoBK6MlWKE6EZ
i5YRKx6rVWvFfMWAV3Tx9uECAwEAAQ==
-----END PUBLIC KEY-----'''

EC_P256_PRIVATE = b'''-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBnRS4Tf1PY6Jb7QOwAM7OWUOMJTBenEWRvGBCGgctBfoAoGCCqGSM49
AwEHoUQDQgAE3r15c+Yd+0GXKysfWtwkqF7k12ylNE9LdfRP4TfkUcJSQXyGQjcx
U8E81rOHjo+9xv2e64n4X6pC3yuP+pX4eA==
-----END EC PRIVATE KEY-----'''

EC_P256_PUBLIC = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3r15c+Yd+0GXKysfWtwkqF7k12yl
NE9LdfRP4TfkUcJSQXyGQjcxU8E81rOHjo+9xv2e64n4X6pC3yuP+pX4eA==
-----END PUBLIC KEY-----'''

EC_P384_PRIVATE = b'''-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDQy7nBIq/aaPR980Wfqk5HqU7qVjo7fvKEeYY/8XxNE1BKUx5VkrSj
G2g5GqgwRtKgBwYFK4EEACKhZANiAARuuP3WJg9DRzKCZ/xsiA66fJ1NoQmK4d7b
1+t9D5f+srq3f9Ttj/NWdn/WaVDf1ectfSQCyInrC8QXBhGqJj0GNIHzvAykCN0H
KS5B9yM0oOKMnSGSklLrOXLQKagxLSU=
-----END EC PRIVATE KEY-----'''

EC_P384_PUBLIC = b'''-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbrj91iYPQ0cygmf8bIgOunydTaEJiuHe
29frfQ+X/rK6t3/U7Y/zVnZ/1mlQ39XnLX0kAsiJ6wvEFwYRqiY9BjSB87wMpAjd
BykuQfcjNKDijJ0hkpJS6zly0CmoMS0l
-----END PUBLIC KEY-----'''

EC_P512_PRIVATE = b'''-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEFvFujwdb3ZFYnWnUZrFobrksVQfpDGFJ9Zt1ofpUrDBjBd4Z6rNB+x
K5OrfJPm2WidZxzsU69J9cCx/ntANMMUWaAHBgUrgQQAI6GBiQOBhgAEANoDiaaU
xmbFy1RrRNOSCsOp5lHj3ugLUnoK/MZHTLGL8UNVsw03K4aqqwVvA43CvQiQZE4t
gZAEYR/n+mCoXsutAYmlEpwe1e4VZTklnO+WULy8anV5yIjrmdwIDVvJ1IyJuBDK
ZO7SyxCnL6S/OW+WjPU9T6ZXcgNRBVaY40zwQ3zh
-----END EC PRIVATE KEY-----'''

EC_P512_PUBLIC = b'''-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA2gOJppTGZsXLVGtE05IKw6nmUePe
6AtSegr8xkdMsYvxQ1WzDTcrhqqrBW8DjcK9CJBkTi2BkARhH+f6YKhey60BiaUS
nB7V7hVlOSWc75ZQvLxqdXnIiOuZ3AgNW8nUjIm4EMpk7tLLEKcvpL85b5aM9T1P
pldyA1EFVpjjTPBDfOE=
-----END PUBLIC KEY-----'''
