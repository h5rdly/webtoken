import webtoken

import pytest



class TestV4Local:
    """
    Tests for v4.local (Symmetric Encryption / XChaCha20-Poly1305)
    """

    def test_v4_local_invalid_key_args(self):

        # Case 1: Empty key
        with pytest.raises(ValueError):
            webtoken.paseto_encode(b"", {"data": "test"}, purpose="local")

        # Case 2: Key too long (Must be exactly 32 bytes for XChaCha20)
        invalid_key = webtoken.random_bytes(65)
        with pytest.raises(ValueError):
            webtoken.paseto_encode(invalid_key, {"data": "test"}, purpose="local")


    def test_v4_local_decrypt_with_wrong_key(self):

        k1 = b"0" * 32
        k2 = b"1" * 32
        payload = {"msg": "Hello world!"}
        
        token = webtoken.paseto_encode(k1, payload, purpose="local")
        
        # Should fail authentication tag verification
        with pytest.raises(ValueError, match="Signature"):
            webtoken.paseto_decode(k2, token, purpose="local")


    def test_v4_local_encrypt_decrypt_cycle(self):

        key = webtoken.random_bytes(32)
        payload = {"data": "this is a secret message"}
        footer = b"footer-data"
        implicit = b"implicit-assertion"

        token = webtoken.paseto_encode(
            key, 
            payload, 
            purpose="local", 
            footer=footer, 
            implicit_assertion=implicit
        )

        assert token.startswith("v4.local.")

        decoded = webtoken.paseto_decode(
            key, 
            token, 
            purpose="local", 
            implicit_assertion=implicit
        )

        assert decoded == payload


class TestV4Public:
    """
    Tests for v4.public (Asymmetric Signing / Ed25519)
    """

    def test_v4_public_verify_with_wrong_key(self):

        payload = {"data": "Hello world!"}

        # Sign with Key 1
        token = webtoken.paseto_encode(PRIVATE_KEY_ED25519_1, payload, purpose="public")

        # Verify with Key 2 (Should fail)
        with pytest.raises(ValueError, match="Signature"):
            webtoken.paseto_decode(PUBLIC_KEY_ED25519_2, token, purpose="public")


    def test_v4_public_sign_verify_cycle(self):

        payload = {"data": "signed message", "exp": "2030-01-01T00:00:00+00:00"}
        footer = b"public-footer"

        # Sign
        token = webtoken.paseto_encode(
            PRIVATE_KEY_ED25519_1, 
            payload, 
            purpose="public", 
            footer=footer
        )

        assert token.startswith("v4.public.")

        # Verify
        decoded = webtoken.paseto_decode(
            PUBLIC_KEY_ED25519_1, 
            token, 
            purpose="public"
        )

        assert decoded == payload

    def test_v4_public_invalid_key_format(self):

        # Passing garbage as a key
        with pytest.raises(ValueError):
            webtoken.paseto_encode(b"not-a-pem-key", {"a": 1}, purpose="public")



## -- Test keys

PRIVATE_KEY_ED25519_1 = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0
-----END PRIVATE KEY-----"""

PUBLIC_KEY_ED25519_1 = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
-----END PUBLIC KEY-----"""

# A different keypair to test failure cases
PRIVATE_KEY_ED25519_2 = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGmfHRcqkCfnAOB7234NNeuBpHUVHSLX4z3s4hsaTEQ8
-----END PRIVATE KEY-----"""

PUBLIC_KEY_ED25519_2 = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAkv4y3wCgwetRuJUt/EKjNJzaTWMKCNcadaGg6obUFdI=
-----END PUBLIC KEY-----"""