import sys
sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

import webtoken
from webtoken import (extract_ed25519_public_key, extract_ed25519_private_key, encode_paserk_key, decode_paserk_key, 
    random_bytes)

import pytest


class TestKey:
    '''
    Tests for stateless PASERK Key handling in 
    '''

    def test_key_new_public_with_wrong_key(self):

        err_msg = 'Invalid Ed25519 key length or format'
        for private_pem in PRIVATE_KEY_RSA, PRIVATE_KEY_ECDSA_P384:
            with pytest.raises(ValueError) as err:
                extract_ed25519_private_key(private_pem)
            assert err_msg in str(err.value)

        for public_pem in PUBLIC_KEY_RSA, PUBLIC_KEY_ECDSA_P384:
            with pytest.raises(ValueError) as err:
                extract_ed25519_public_key(public_pem)
            assert err_msg in str(err.value)


    @pytest.mark.parametrize(
        'purpose, key, msg',
        [
            ('xxx', random_bytes(32), 'Invalid purpose: xxx.'),
            # ("public", "-----BEGIN BAD", "Invalid or unsupported PEM format."),
        ],
    )
    def test_key_new_with_invalid_arg(self, purpose, key, msg):
        with pytest.raises(ValueError) as err:
            encode_paserk_key(purpose, key)
        assert msg in str(err.value)


    @pytest.mark.parametrize(
        'paserk',
        [
            'k4.local.AAAAAAAAAAAAAAAA',
            'k4.public.AAAAAAAAAAAAAAAA',
        ],
    )
    def test_key_from_paserk_with_wrapping_key_and_password(self, paserk):

        with pytest.raises(ValueError) as err:
            decode_paserk_key(paserk, wrapping_key='xxx', password='yyy')
        assert 'Only one of wrapping_key or password should be specified.' in str(err.value)


    @pytest.mark.parametrize(
        'paserk, msg',
        [
            ('k4.local.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: local.'),
            ('k4.public.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: public.'),
        ],
    )
    def test_key_from_paserk_with_password_for_wrong_paserk(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            decode_paserk_key(paserk, password='yyy')
        assert msg in str(err.value)


    @pytest.mark.parametrize(
        'paserk, msg',
        [
            ('v4.local.AAAAAAAAAAAAAAAA', 'Invalid PASERK version: v4.'),
            ('*.local.AAAAAAAAAAAAAAAA', 'Invalid PASERK version: *.'),
            ('k4.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: xxx.'),
        ],
    )
    def test_key_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            decode_paserk_key(paserk)
        assert msg in str(err.value)


    def test_key_from_paserk_for_local_with_wrong_wrapping_key(self):

        wpk = encode_paserk_key('local', random_bytes(32), wrapping_key='1' * 32)
        with pytest.raises(ValueError) as err:
            decode_paserk_key(wpk, wrapping_key='2' * 32)
        assert 'Failed to unwrap a key.' in str(err.value)


    def test_key_from_paserk_for_local_with_wrong_password(self):
        
        wpk = encode_paserk_key('local', random_bytes(32), password='password1')
        with pytest.raises(ValueError) as err:
            decode_paserk_key(wpk, password='password2')
        assert 'Failed to unwrap a key.' in str(err.value)


    def test_key_from_paserk_for_private_key_with_wrong_wrapping_key(self):

        key = extract_ed25519_private_key(PRIVATE_KEY_ED25519)
        wpk = encode_paserk_key('secret', key, wrapping_key='1' * 32)
        with pytest.raises(ValueError) as err:
            decode_paserk_key(wpk, wrapping_key='2' * 32)
        assert 'Failed to unwrap a key.' in str(err.value)


    def test_key_from_paserk_for_public_key_with_wrapping_key(self):

        key = extract_ed25519_public_key(PUBLIC_KEY_ED25519)
        with pytest.raises(ValueError) as err:
            encode_paserk_key('public', key, wrapping_key=random_bytes(32))
        assert 'Public key cannot be wrapped.' in str(err.value)


    def test_key_from_paserk_for_public_key_with_password(self):

        key = extract_ed25519_public_key(PUBLIC_KEY_ED25519)
        with pytest.raises(ValueError) as err:
            encode_paserk_key('public', key, password='password123')
        assert 'Public key cannot be wrapped.' in str(err.value)


    def test_key_to_paserk_public(self):

        key = extract_ed25519_public_key(PUBLIC_KEY_ED25519)
        assert encode_paserk_key('public', key).startswith('k4.public.')


    def test_key_to_paserk_secret(self):

        key = extract_ed25519_private_key(PRIVATE_KEY_ED25519)
        assert encode_paserk_key('secret', key).startswith('k4.secret.')


    def test_key_to_paserk_secret_with_wrapping_key_and_password(self):

        for (purpose, key) in (
            ('local', random_bytes(32)), 
            ('public', extract_ed25519_public_key(PUBLIC_KEY_ED25519))
        ):
            with pytest.raises(ValueError) as err:
                encode_paserk_key(purpose, key, wrapping_key='xxx', password='yyy')
            assert 'Only one of wrapping_key or password should be specified.' in str(err.value)



## -- Test data

PRIVATE_KEY_RSA = '''
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE6bVp25YxM72Z
2h27jFz6a9A3tJ3pE6+X1Cq3KkE6d9D0lG5y7f3w+A8X2p4n8C4s4l/h2L6R8Pq0
Yy7R5d7t9s2B0U9F3a5X6e7x1w3w9X3K5X9e9D0b1a0e5d0e2A8L7A6B5C4D3E2F1A0B
-----END PRIVATE KEY-----'''

PUBLIC_KEY_RSA = '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxOm1aduWMT[... insert ...]
-----END PUBLIC KEY-----'''

PRIVATE_KEY_ED25519 = '''
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0
-----END PRIVATE KEY-----'''

PUBLIC_KEY_ED25519 = '''
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
-----END PUBLIC KEY-----'''

PRIVATE_KEY_ECDSA_P384 = '''
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA/J12hD4gA2oFfV7X6
...
-----END PRIVATE KEY-----'''

PUBLIC_KEY_ECDSA_P384 = '''
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEX5f4A6sD7cQ5xV5Z3lA3xL2C6eK5zE5V
...
-----END PUBLIC KEY-----'''