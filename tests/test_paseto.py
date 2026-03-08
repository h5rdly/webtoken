import sys, time, json
from datetime import datetime, timedelta, timezone
sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

import webtoken
from webtoken import Key, VerifyError
from keys_and_vectors import (PRIVATE_KEY_ED25519, PUBLIC_KEY_ED25519, PUBLIC_KEY_ED25519_2, 
    PUBLIC_KEY_ECDSA_P384, PUBLIC_KEY_RSA)

import pytest


class InvalidSerializer:
    def __init__(self):
        self.dumps = 'not a function'


class InvalidSerializer2:
    def dumps(self, *args):
        raise NotImplementedError('Not implemented')


class InvalidDeserializer:
    def __init__(self):
        self.loads = 'not a function'


class InvalidDeserializer2:
    def loads(self, *args):
        raise NotImplementedError('Not implemented')


class TestPyseto:
    '''
    Tests for webtoken.paseto_encode and decode.
    '''

    @pytest.mark.parametrize(
        'key, msg',
        [
            (PUBLIC_KEY_ED25519, 'A public key cannot be used for signing',),
        ],
    )
    def test_encode_with_public_key(self, key, msg):

        k = Key.new('public', key)
        with pytest.raises(ValueError) as err:
            webtoken.paseto_encode(k, b'Hello world!')

        assert msg in str(err.value)


    @pytest.mark.parametrize(
        'serializer, msg',
        [
            (
                None,
                'serializer should be specified for the payload object',
            ),
            (
                {},
                'serializer should be specified for the payload object',
            ),
            (
                [],
                'serializer should be specified for the payload object',
            ),
            (
                '',
                'serializer should be specified for the payload object',
            ),
            (
                b'',
                'serializer should be specified for the payload object',
            ),
            (
                {'key': 'value'},
                'serializer should have dumps()',
            ),
            (
                InvalidSerializer(),
                'serializer should have dumps()',
            ),
            (
                InvalidSerializer2(),
                'Failed to serialize the payload.',
            ),
        ],
    )
    def test_encode_object_payload_with_invalid_serializer(self, serializer, msg):
        
        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        with pytest.raises(ValueError) as err:
            webtoken.paseto_encode(
                private_key,
                {'data': 'this is a signed message', 'exp': '2022-01-01T00:00:00+00:00',},
                serializer=serializer,
            )
        assert msg in str(err.value)


    @pytest.mark.parametrize(
        'serializer, msg',
        [
            (
                None,
                'serializer should be specified for the footer object',
            ),
            (
                {},
                'serializer should be specified for the footer object',
            ),
            (
                [],
                'serializer should be specified for the footer object',
            ),
            (
                '',
                'serializer should be specified for the footer object',
            ),
            (
                b'',
                'serializer should be specified for the footer object',
            ),
            (
                {'key': 'value'},
                'serializer should have dumps()',
            ),
            (
                InvalidSerializer(),
                'serializer should have dumps()',
            ),
            (
                InvalidSerializer2(),
                'Failed to serialize the footer.',
            ),
        ],
    )
    def test_encode_object_footer_with_invalid_serializer(self, serializer, msg):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        private_key = Key.new(purpose='public', key=private_key_pem)
        with pytest.raises(ValueError) as err:
            webtoken.paseto_encode(
                private_key, b'Hello world!', footer={'kid': 'xxxxxx',}, serializer=serializer,
            )
            
        assert msg in str(err.value)


    @pytest.mark.parametrize(
        'key, msg',
        [
            (PUBLIC_KEY_ED25519, 'Invalid payload'),
        ],
    )
    def test_decode_with_invalid_payload(self, key, msg):
        k = Key.new('public', key)
        with pytest.raises(ValueError) as err:
            webtoken.paseto_decode(k, f'v4.public.11111111')
        assert msg in str(err.value)


    ## Modified from ooriginal suite - webtoken only supports V4
    @pytest.mark.parametrize(
        'public_key',
        [
            (PUBLIC_KEY_RSA),
            (PUBLIC_KEY_ECDSA_P384),
        ],
    )
    def test_decode_with_another_version_key(self, public_key):

        with pytest.raises(ValueError) as err:
            pk = Key.new("public", public_key)
        assert "The key is not Ed25519 key." in str(err.value)


    @pytest.mark.parametrize(
        'deserializer, msg',
        [
            (
                {'key': 'value'},
                'deserializer should have loads()',
            ),
            (
                InvalidDeserializer(),
                'deserializer should have loads()',
            ),
            (
                InvalidDeserializer2(),
                'Failed to deserialize the payload',
            ),
        ],
    )
    def test_decode_object_payload_with_invalid_deserializer(self, deserializer, msg):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'
        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key, {'data': 'this is a signed message', 'exp': '2099-01-01T00:00:00+00:00'},
        )

        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(ValueError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=deserializer)

        assert msg in str(err.value)


    def test_decode_bytes_footer_with_deserializer(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'
        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key,
            {'data': 'this is a signed message', 'exp': '2099-01-01T00:00:00+00:00'},
            footer=b'This is a footer.',
        )
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json)

        assert isinstance(decoded.footer, bytes)
        assert decoded.footer == b'This is a footer.'


    def test_decode_object_payload_with_invalid_exp(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(private_key, {'data': 'this is a signed message', 'exp': 'xxxxx'},)
        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(VerifyError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=json)
        assert 'Invalid exp' in str(err.value)


    def test_decode_object_payload_with_expired_exp(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(private_key, {'data': 'this is a signed message'}, exp_seconds=0.01,)
        time.sleep(0.1)
        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(VerifyError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=json)
        assert 'Token has expired' in str(err.value)


    def test_decode_object_payload_with_aud(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(private_key, {'data': 'this is a signed message', 'aud': '12345'},)
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json, aud='12345')

        assert decoded.payload['aud'] == '12345'


    def test_decode_object_payload_without_aud(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(private_key, {'data': 'this is a signed message'},)
        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(VerifyError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=json, aud='12345')

        assert 'aud verification failed' in str(err.value)


    def test_decode_object_payload_with_invalid_aud(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(private_key, {'data': 'this is a signed message', 'aud': '12345'},)
        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(VerifyError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=json, aud='1234x')
        assert 'aud verification failed' in str(err.value)


    def test_decode_object_payload_with_invalid_nbf(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(private_key, {'data': 'this is a signed message', 'nbf': 'xxxxx'},)
        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(VerifyError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=json)
        assert 'Invalid nbf' in str(err.value)


    def test_decode_object_payload_with_future_nbf(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        now = datetime.now(tz=timezone.utc)
        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key,
            {
                'data': 'this is a signed message',
                'nbf': (now + timedelta(seconds=10)).isoformat(timespec='seconds'),
            },
        )
        public_key = Key.new(purpose='public', key=public_key_pem)
        with pytest.raises(VerifyError) as err:
            webtoken.paseto_decode(public_key, token, deserializer=json)
        assert 'Token is not yet valid' in str(err.value)


    def test_decode_with_empty_list_of_keys(self):

        sk = Key.new('public', PRIVATE_KEY_ED25519)
        token = webtoken.paseto_encode(sk, 'Hello world!')
        with pytest.raises(ValueError) as err:
            webtoken.paseto_decode([], token)
        assert 'key is not found for verifying the token' in str(err.value)


    ## Modified from ooriginal suite - webtoken only supports V4
    # def test_decode_with_different_keys(self):
        
    #     sk = Key.new('public', PRIVATE_KEY_ED25519)
    #     pk1 = Key.new('public', PUBLIC_KEY_RSA)
    #     # pk2 = Key.new('public', PUBLIC_KEY_ED25519)
    #     pk2 = Key.new('public', PUBLIC_KEY_ECDSA_P384)
    #     token = webtoken.paseto_encode(sk, 'Hello world!')
    #     with pytest.raises(ValueError) as err:
    #         webtoken.paseto_decode([pk1, pk2], token)
    #     assert 'key is not found for verifying the token' in str(err.value)


    ## Modified from original suite - webtoken only supports V4 - this actually becomes the same as test_decode_with_multiple_keys_have_same_header
    def test_decode_with_multiple_keys(self):

        sk = Key.new('public', PRIVATE_KEY_ED25519)
        token = webtoken.paseto_encode(sk, b'Hello world!')

        pk2 = Key.new('public', PUBLIC_KEY_ED25519)
        pk4 = Key.new('public', PUBLIC_KEY_ED25519)
        decoded = webtoken.paseto_decode([pk2, pk4], token)

        assert decoded.payload == b'Hello world!'


    def test_decode_with_multiple_keys_have_same_header(self):

        sk = Key.new('public', PRIVATE_KEY_ED25519)
        token = webtoken.paseto_encode(sk, b'Hello world!')
        pk2 = Key.new('public', PUBLIC_KEY_ED25519_2)
        pk1 = Key.new('public', PUBLIC_KEY_ED25519)
        decoded = webtoken.paseto_decode([pk2, pk1], token)

        assert decoded.payload == b'Hello world!'

