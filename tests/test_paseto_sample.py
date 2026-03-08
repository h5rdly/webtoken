import sys, time, json
from datetime import datetime, timedelta, timezone
sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

import webtoken
from webtoken import Key, json_dumps

from keys_and_vectors import (
    PRIVATE_KEY_ED25519, PUBLIC_KEY_ED25519, PRIVATE_KEY_X25519, PUBLIC_KEY_X25519
)
import pytest


class TestSample:

    def test_sample_v4_local_old(self):

        key = Key.new('local', b'our-secret-that-is-exactly-32-bt')
        token = webtoken.paseto_encode(
            key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )

        decoded = webtoken.paseto_decode(key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_v4_public_old(self):
        
        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new('public', private_key_pem)
        token = webtoken.paseto_encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        public_key = Key.new('public', public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token)
        print(token)
        assert (token == 'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjA5OS0wMS0wMVQwMDowMDowMCswMDowMCJ90a1IpE1hvRecrkiOgzz329s2UJEX98qghZKmAcMxv-jrojwnxslMRzDVfRlcKKGbx7Xdgh8yyRtKukLfBC-LBw'
        )
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_v4_local(self):

        key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        token = webtoken.paseto_encode(
            key,
            b'{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}',
        )

        decoded = webtoken.paseto_decode(key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_v4_public(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token)

        assert (token == "v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjA5OS0wMS0wMVQwMDowMDowMCswMDowMCJ90a1IpE1hvRecrkiOgzz329s2UJEX98qghZKmAcMxv-jrojwnxslMRzDVfRlcKKGbx7Xdgh8yyRtKukLfBC-LBw"
        )
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_v4_public_with_serializer(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key, {"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"},)
        
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json, validate_claims=False)

        assert (token == "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"
        )
        assert decoded.payload["data"] == "this is a signed message"
        assert decoded.payload["exp"] == "2022-01-01T00:00:00+00:00"


    def test_sample_v4_local_with_serializer(self):
        key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        token = webtoken.paseto_encode(
            key,
            {"data": "this is a signed message"},
        )
        decoded = webtoken.paseto_decode(key, token, deserializer=json)
        assert decoded.payload["data"] == "this is a signed message"


    def test_sample_v4_public_with_serializer_and_exp(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'
        now = datetime.now(tz=timezone.utc)

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key,
            {"data": "this is a signed message"},
            exp_seconds=3600,
        )
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert datetime.fromisoformat(decoded.payload["exp"]) >= now + timedelta(seconds=3600 - 1)


    def test_sample_v4_public_with_paseto_class(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'
        private_key = Key.new(purpose='public', key=private_key_pem)
        now = datetime.now(tz=timezone.utc)

        token = webtoken.paseto_encode(
            private_key, {"data": "this is a signed message"}, add_iat=True, exp_seconds=3600
        )
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert "iat" in decoded.payload
        assert "exp" in decoded.payload
        assert datetime.fromisoformat(decoded.payload["exp"]) >= now + timedelta(seconds=3600 - 1)


    def test_sample_v4_public_with_paseto_class_and_leeway(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'
        now = datetime.now(tz=timezone.utc)

        private_key = Key.new(purpose='public', key=private_key_pem)
        token = webtoken.paseto_encode(
            private_key, {"data": "this is a signed message"}, add_iat=True, exp_seconds=3600
        )
        public_key = Key.new(purpose='public', key=public_key_pem)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert "iat" in decoded.payload
        assert "exp" in decoded.payload
        assert datetime.fromisoformat(decoded.payload["exp"]) >= now


    def test_sample_v4_public_with_kid(self):

        private_key_pem = b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----'
        public_key_pem = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----'
        private_key = Key.new(purpose='public', key=private_key_pem)
        public_key = Key.new(purpose='public', key=public_key_pem)
        now = datetime.now(tz=timezone.utc)
        nbf = (now - timedelta(seconds=10)).isoformat(timespec="seconds")
        token = webtoken.paseto_encode(private_key, {"data": "this is a signed message", "nbf": nbf}, 
            footer={"kid": public_key.to_paserk_id()}, add_iat=True, exp_seconds=3600,)
        decoded = webtoken.paseto_decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert "iat" in decoded.payload
        assert "exp" in decoded.payload
        assert "kid" in decoded.footer
        assert decoded.footer["kid"] == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
        assert datetime.fromisoformat(decoded.payload["exp"]) >= now

    def test_sample_paserk(self):

        symmetric_key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

        token = webtoken.paseto_encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        decoded = webtoken.paseto_decode(public_key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'

        assert symmetric_key.to_paserk() == 'k4.local.b3VyLXNlY3JldC10aGF0LWlzLWV4YWN0bHktMzItYnQ'
        assert (
            private_key.to_paserk()
            == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        assert public_key.to_paserk() == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"


    def test_sample_paserk_id(self):

        symmetric_key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

        assert symmetric_key.to_paserk_id() == "k4.lid.p_Ozdr2GZmknXvTdcxUGCDdQ2F2WODGIC_1rr0LJvq71"
        assert private_key.to_paserk_id() == "k4.sid.9gZFsAQuXhu9lif2pV3rCDjOewsMF4qb4RHGhc0zUklt"
        assert public_key.to_paserk_id() == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"


    def test_sample_paserk_key_wrapping_local(self):

        raw_key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        wrapping_key = webtoken.random_bytes(32)
        wpk = raw_key.to_paserk(wrapping_key=wrapping_key)

        # assert wpk == "k4.local-wrap.pie.TNKEwC4K1xBcgJ_GiwWAoRlQFE33HJO3oN9DHEZ05pieSCd-W7bgAL64VG9TZ_pBkuNBFHNrfOGHtnfnhYGdbz5-x3CxShhPJxg"

        unwrapped_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
        token = webtoken.paseto_encode(
            raw_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        decoded = webtoken.paseto_decode(unwrapped_key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_paserk_key_wrapping_public(self):

        raw_private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")
        wrapping_key = webtoken.random_bytes(32)
        wpk = raw_private_key.to_paserk(wrapping_key=wrapping_key)

        # assert wpk == "k4.secret-wrap.pie.excv7V4-NaECy5hpji-tkSkMvyjsAgNxA-mGALgdjyvGNyDlTb89bJ35R1e3tILgbMpEW5WXMXzySe2T-sBz-ZAcs1j7rbD3ZWvsBTM6K5N9wWfAxbR4ppCXH_H5__9yY-kBaF2NimyAJyduhOhSmqLm6TTSucpAOakEJOXePW8"

        unwrapped_private_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
        token = webtoken.paseto_encode(
            unwrapped_private_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        decoded = webtoken.paseto_decode(public_key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_paserk_password_local(self):

        raw_key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        wpk = raw_key.to_paserk(password="our-secret")

        # assert wpk == "k4.local-pw.HrCs9Pu-2LB0l7jkHB-x2gAAAAAA8AAAAAAAAgAAAAGttW0IHZjQCHJdg-Vc3tqO_GSLR4vzLl-yrKk2I-l8YHj6jWpC0lQB2Z7uzTtVyV1rd_EZQPzHdw5VOtyucP0FkCU"

        unwrapped_key = Key.from_paserk(wpk, password="our-secret")
        token = webtoken.paseto_encode(
            raw_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        decoded = webtoken.paseto_decode(unwrapped_key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_paserk_password_public(self):
        raw_private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")
        wpk = raw_private_key.to_paserk(password="our-secret")

        # assert wpk == "k4.secret-pw.MEMW4K1MaD5nWigCLyEyFAAAAAAA8AAAAAAAAgAAAAFU-tArtryNVjS2n2hCYiM11V6tOyuIog69Bjb0yNZanrLJ3afGclb3kPzQ6IhK8ob9E4QgRdEALGWCizZ0RCPFF_M95IQDfmdYKC0Er656UgKUK4UKG9JlxP4o81UwoJoZYz_D1zTlltipEa5RiNvUtNU8vLKoGSY"

        unwrapped_private_key = Key.from_paserk(wpk, password="our-secret")
        token = webtoken.paseto_encode(
            unwrapped_private_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        decoded = webtoken.paseto_decode(public_key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_paserk_seal(self):
        raw_key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        token = webtoken.paseto_encode(
            raw_key,
            b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
        )
        sealed_key = raw_key.to_paserk(sealing_key=PUBLIC_KEY_X25519)

        unsealed_key = Key.from_paserk(sealed_key, unsealing_key=PRIVATE_KEY_X25519)
        decoded = webtoken.paseto_decode(unsealed_key, token)
        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'


    def test_sample_rtd_v4_public(self):

        private_key = Key.new('public', PRIVATE_KEY_ED25519)
        token = webtoken.paseto_encode(
            private_key,
            payload=b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        public_key = Key.new('public', PUBLIC_KEY_ED25519)
        decoded = webtoken.paseto_decode(public_key, token, implicit_assertion=b"xyz")

        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.purpose == 'public'


    def test_sample_rtd_v4_local(self):
        key = Key.new(purpose='local', key=b"our-secret-that-is-exactly-32-bt")
        token = webtoken.paseto_encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2099-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        decoded = webtoken.paseto_decode(key, token, implicit_assertion=b"xyz")

        assert json_dumps(decoded.payload) =='{"data":"this is a signed message","exp":"2099-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.purpose == 'local'


