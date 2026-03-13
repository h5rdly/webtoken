import sys
sys.path.append(__file__.replace('\\', '/').rsplit("/", 2)[0])

import webtoken
from webtoken import InvalidSignatureError

from unittest import TestCase
import pytest


def test_dir_c20p():

    key = webtoken.random_bytes(32)
    protected = {"alg": "dir", "enc": "C20P"}
    
    token = webtoken.encrypt_compact(protected, b"hello", key)
    assert token.count(".") == 4
    
    obj = webtoken.decrypt_compact(token, key)
    assert obj == b"hello"

    key2 = webtoken.random_bytes(32)
    # self.assertRaises(InvalidSignatureError, decrypt_compact, token, key2)
    with pytest.raises(InvalidSignatureError):
        webtoken.decrypt_compact(token, key2)


def test_dir_xc20p():

    key = webtoken.random_bytes(32)
    protected = {"alg": "dir", "enc": "XC20P"}
    
    token = webtoken.encrypt_compact(protected, b"hello", key)
    assert token.count(".") == 4
    
    obj = webtoken.decrypt_compact(token, key)
    assert obj == b"hello"


def test_xc20p_content_encryption_decryption():
    
    # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e"
    )

    cek = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    iv = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")

    ciphertext, tag = webtoken.encrypt_xc20p(cek, plaintext, aad=aad, nonce=iv)
    
    assert ciphertext == bytes.fromhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
            "21f9664c97637da9768812f615c68b13b52e"
        )
    assert tag == bytes.fromhex("c0875924c1c7987947deafd8780acf49")

    result = webtoken.decrypt_xc20p(cek, ciphertext, tag, aad=aad, nonce=iv)
    assert plaintext == result

