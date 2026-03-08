import sys
sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

import webtoken
from webtoken import Key, EncryptError, DecryptError

from keys_and_vectors import PUBLIC_KEY_ED25519, PUBLIC_KEY_ED25519_2, PRIVATE_KEY_ED25519
import pytest


class TestV4Local:

    @pytest.mark.parametrize(
        'key, msg',
        [
            ('', 'key must be specified.'),
            (webtoken.random_bytes(65), 'key length must be up to 64 bytes.'),
        ],
    )
    def test_v4_local_new_with_invalid_arg(self, key, msg):

        with pytest.raises(ValueError) as err:
           Key.new("local", key)
        assert msg in str(err.value)

    def test_v4_local_decrypt_via_decode_with_wrong_key(self):

        k1 = Key.new('local', 'our-secret'.ljust(32, '\0'))
        k2 = Key.new('local','others-secret'.ljust(32, '\0'))
        token = webtoken.paseto_encode(k1, 'Hello world!', purpose='local')
        with pytest.raises(DecryptError) as err:
            webtoken.paseto_decode(k2, token)
        assert 'Failed to decrypt' in str(err.value)


    def test_v4_local_encrypt_with_invalid_arg(self):

        key = Key.new('local','our-secret'.ljust(32, '\0'))
        with pytest.raises(EncryptError) as err:
            key.encrypt(None)
        assert 'Failed to encrypt' in str(err.value)


    @pytest.mark.parametrize(
        'nonce',
        [
            webtoken.random_bytes(1),
            webtoken.random_bytes(8),
            webtoken.random_bytes(31),
            webtoken.random_bytes(33),
            webtoken.random_bytes(64),
        ],
    )
    def test_v4_local_encrypt_via_encode_with_wrong_nonce(self, nonce):

        key = Key.new('local','our-secret'.ljust(32, '\0'))
        with pytest.raises(ValueError) as err:
            webtoken.paseto_encode(key, 'Hello world!', purpose='local', nonce=nonce)

        assert 'nonce must be 32 bytes long.' in str(err.value)


    @pytest.mark.parametrize(
        'paserk, msg',
        [
            ('xx.local.AAAAAAAAAAAAAAAA', 'Invalid PASERK version: xx.'),
            ('k1.local.AAAAAAAAAAAAAAAA', 'Invalid PASERK version: k1.'),
            ('k4.local.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK format.'),
            ('k4.public.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK format.'),
            ('k4.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: xxx.'),
            ('k4.public.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: public.'),
        ],
    )
    def test_v4_local_from_paserk_with_invalid_args(self, paserk, msg):
        with pytest.raises(ValueError) as err:
            webtoken.decode_paserk_key(paserk, 'local')
        assert msg in str(err.value)


    def test_v4_local_to_peer_paserk_id(self):
        k = Key.new('local', 'our-secret'.ljust(32, '\0'))
        assert k.to_peer_paserk_id() == ''


class TestV4Public:

    def test_v4_public_to_paserk_id(self):

        sk = Key.new('public', PRIVATE_KEY_ED25519)
        pk = Key.new('public', PUBLIC_KEY_ED25519)
        
        # Secret keys export their own sid, public keys export their pid
        assert sk.to_peer_paserk_id() == pk.to_paserk_id()
        assert pk.to_peer_paserk_id() == ''


    def test_v4_public_verify_via_encode_with_wrong_key(self):

        sk = Key.new('public', PRIVATE_KEY_ED25519)
        pk = Key.new('public', PUBLIC_KEY_ED25519_2)
        token = webtoken.paseto_encode(sk, 'Hello world!', purpose='public')
        with pytest.raises(ValueError) as err:
            webtoken.paseto_decode(pk, token, purpose='public')

        assert 'Signature verification failed' in str(err.value)

        
    @pytest.mark.parametrize(
        'paserk, msg',
        [
            ('xx.public.AAAAAAAAAAAAAAAA', 'Invalid PASERK version: xx.'),
            ('k1.public.AAAAAAAAAAAAAAAA', 'Invalid PASERK version: k1.'),
            ('k4.public.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK format.'),
            ('k4.local.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK format.'),
            ('k4.xxx.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: xxx.'),
            ('k4.local.AAAAAAAAAAAAAAAA', 'Invalid PASERK type: local.'),
        ],
    )
    def test_v4_public_from_paserk_with_invalid_args(self, paserk, msg):

        valid_dummy_token = 'v4.public.' + ('A' * 86)
        with pytest.raises(ValueError) as err:
            webtoken.paseto_decode(paserk, valid_dummy_token, purpose='public')
        assert msg in str(err.value)


