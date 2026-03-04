
import sys, json
sys.path.append(__file__.replace('\\', '/').rsplit("/", 2)[0])

import webtoken
from webtoken import Key

import pytest


class TestWithTestVectorsV4:

    def test_with_test_vectors(self):

        for v in webtoken.json_loads(V4)['tests']:

            token = v["token"].encode('utf8')
            payload = v["payload"]
            footer = v["footer"].encode('utf8')
            implicit_assertion = v["implicit-assertion"].encode('utf8')

            purpose = v["name"].split("-")[1]

            if v["expect-fail"]:
                if "public-key" not in v:
                    nonce = bytes.fromhex(v["nonce"])
                    key = bytes.fromhex(v["key"])

                    k = Key.new("local", key=key)
                    with pytest.raises(ValueError) as err:
                        webtoken.paseto_encode(k, payload, footer, implicit_assertion, nonce=nonce)
                        pytest.fail("encode should fail.")
                    assert "payload should be bytes, str or dict." in str(err.value)
                    return

                secret_key_pem = v["secret-key"] if version == 1 else v["secret-key-pem"]
                public_key_pem = v["public-key"] if version == 1 else v["public-key-pem"]

                sk = Key.new("public", secret_key_pem)
                with pytest.raises(ValueError) as err:
                    webtoken.paseto_encode(sk, payload, footer, implicit_assertion)
                    pytest.fail("encode should fail.")
                assert "payload should be bytes, str or dict." in str(err.value)
                return

            payload = json.loads(payload)
            if purpose == "E":
                nonce = bytes.fromhex(v["nonce"])
                key = bytes.fromhex(v["key"])

                k = Key.new("local", key=key)
                encoded = webtoken.paseto_encode(k, payload, footer, implicit_assertion, nonce=nonce)
                decoded_token = webtoken.paseto_decode(k, token, implicit_assertion)
                decoded = webtoken.paseto_decode(k, encoded, implicit_assertion)
                assert payload == decoded_token == decoded
                return

            if purpose == "S":
                secret_key_pem = v["secret-key"] if version == 1 else v["secret-key-pem"]
                public_key_pem = v["public-key"] if version == 1 else v["public-key-pem"]

                sk = Key.new("public", secret_key_pem)
                encoded = webtoken.paseto_encode(sk, payload, footer, implicit_assertion)
                pk = Key.new("public", public_key_pem)
                decoded_token = webtoken.paseto_decode(pk, token, implicit_assertion)
                decoded = webtoken.paseto_decode(pk, encoded, implicit_assertion)
                assert payload == decoded_token == decoded

                secret_key = bytes.fromhex(v["secret-key"])
                public_key = bytes.fromhex(v["public-key"])

                sk = Key.from_asymmetric_key_params(d=secret_key[0:32])
                encoded = webtoken.paseto_encode(sk, payload, footer, implicit_assertion)
                pk = Key.from_asymmetric_key_params(x=public_key)
                decoded_token = webtoken.paseto_decode(pk, token, implicit_assertion)
                decoded = webtoken.paseto_decode(pk, encoded, implicit_assertion)
                assert payload == decoded_token == decoded

                return

            pytest.fail(f"Invalid test name: {v['name']}")


    def test_with_test_vectors_paserk_public(self):

        for v in webtoken.json_loads(K4_PUBLIC)['tests']:
            k = Key.from_asymmetric_key_params(x=bytes.fromhex(v["key"]))
            assert k.to_paserk() == v["paserk"]
            k2 = Key.from_paserk(v["paserk"])
            assert k2.to_paserk() == v["paserk"]


    def test_with_test_vectors_paserk_secret(self):

        for v in webtoken.json_loads(K4_SECRET)['tests']:
            k = Key.from_asymmetric_key_params(d=bytes.fromhex(v["secret-key-seed"]))
            assert k.to_paserk() == v["paserk"]
            k2 = Key.from_paserk(v["paserk"])
            assert k2.to_paserk() == v["paserk"]


    def test_with_test_vectors_paserk_local(self):

        for v in webtoken.json_loads(K4_LOCAL)['tests']:
            k = Key.new("local", bytes.fromhex(v["key"]))
            k2 = Key.from_paserk(v["paserk"])
            assert k.to_paserk() == v["paserk"]
            assert k2.to_paserk() == v["paserk"]


    def test_with_test_vectors_paserk_pid(self):

        for v in webtoken.json_loads(K4_PID)['tests']:
            k = Key.from_asymmetric_key_params(x=bytes.fromhex(v["key"]))
            assert k.to_paserk_id() == v["paserk"]


    def test_with_test_vectors_paserk_sid(self):

        for v in webtoken.json_loads(K4_SID)['tests']:
            k = Key.from_asymmetric_key_params(d=bytes.fromhex(v["seed"]))
            assert k.to_paserk_id() == v["paserk"]


    def test_with_test_vectors_paserk_lid(self):

        for v in webtoken.json_loads(K4_LID)['tests']:
            k = Key.new("local", bytes.fromhex(v["key"]))
            assert k.to_paserk_id() == v["paserk"]


    def test_with_test_vectors_paserk_local_wrap_pie(self):

        for v in webtoken.json_loads(K4_LOCAL_WRAP_PIE)['tests']:
            k = Key.from_paserk(v["paserk"], wrapping_key=bytes.fromhex(v["wrapping-key"]))

            k1 = Key.new("local", bytes.fromhex(v["unwrapped"]))
            wpk = k1.to_paserk(wrapping_key=bytes.fromhex(v["wrapping-key"]))
            k2 = Key.from_paserk(wpk, wrapping_key=bytes.fromhex(v["wrapping-key"]))

            t = webtoken.paseto_encode(k, b"Hello world!")
            d = webtoken.paseto_decode(k, t)
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d == d1 == d2 == b"Hello world!"

            t = webtoken.paseto_encode(k1, b"Hello world!")
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d1 == d2 == b"Hello world!"

            d = webtoken.paseto_decode(k, t)
            assert d == b"Hello world!"


    def test_with_test_vectors_paserk_secret_wrap_pie(self):
        
        for v in webtoken.json_loads(K4_SECRET_WRAP_PIE)['tests']:
            k = Key.from_paserk(v["paserk"], wrapping_key=bytes.fromhex(v["wrapping-key"]))
            k1 = Key.from_asymmetric_key_params(d=bytes.fromhex(v["unwrapped"])[0:32])

            wpk = k1.to_paserk(wrapping_key=bytes.fromhex(v["wrapping-key"]))
            k2 = Key.from_paserk(wpk, wrapping_key=bytes.fromhex(v["wrapping-key"]))

            t = webtoken.paseto_encode(k, b"Hello world!")
            d = webtoken.paseto_decode(k, t)
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d == d1 == d2 == b"Hello world!"

            t = webtoken.paseto_encode(k1, b"Hello world!")
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d1 == d2 == b"Hello world!"

            d = webtoken.paseto_decode(k, t)
            assert d == b"Hello world!"


    def test_with_test_vectors_paserk_local_pw(self):

        for v in webtoken.json_loads(K4_LOCAL_PW)['tests']:
            password = v["password"]
            k = Key.from_paserk(v["paserk"], password=password)

            k1 = Key.new("local", bytes.fromhex(v["unwrapped"]))
            wpk = k1.to_paserk(password=password,)

            k2 = Key.from_paserk(wpk, password=password)
            assert k1.key_bytes == k2.key_bytes

            t = webtoken.paseto_encode(k, b"Hello world!")
            d = webtoken.paseto_decode(k, t)
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d == d1 == d2 == b"Hello world!"

            t = webtoken.paseto_encode(k1, b"Hello world!")
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d1 == d2 == b"Hello world!"

            d = webtoken.paseto_decode(k, t)
            assert d == b"Hello world!"


    def test_with_test_vectors_paserk_secret_pw(self):

        for v in webtoken.json_loads(K4_SECRET_PW)['tests']:
            k = Key.from_paserk(v["paserk"], password=v["password"])
            k1 = Key.from_asymmetric_key_params(d=bytes.fromhex(v["unwrapped"])[0:32])
            wpk = k1.to_paserk(password=v["password"])

            k2 = Key.from_paserk(wpk, password=v["password"])

            t = webtoken.paseto_encode(k, b"Hello world!")
            d = webtoken.paseto_decode(k, t)
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d == d1 == d2 == b"Hello world!"

            t = webtoken.paseto_encode(k1, b"Hello world!")
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d1 == d2 == b"Hello world!"

            d = webtoken.paseto_decode(k, t)
            assert d == b"Hello world!"


    def test_with_test_vectors_paserk_seal_v4(self):

        for v in webtoken.json_loads(K4_SEAL)['tests']:
            sk_ed25519 = bytes.fromhex(v["sealing-secret-key"])[0:32]
            unsealing_key = webtoken.ed25519_seed_to_x25519_private(sk_ed25519)
            sealing_key = webtoken.x25519_public_from_private(unsealing_key)
            
            k = Key.from_paserk(v["paserk"], unsealing_key=unsealing_key)
            k1 = Key.new("local", bytes.fromhex(v["unsealed"]))
            wpk = k1.to_paserk(sealing_key=sealing_key)
            k2 = Key.from_paserk(wpk, unsealing_key=unsealing_key)
            assert k1.key_bytes == k2.key_bytes

            t = webtoken.paseto_encode(k, b"Hello world!")
            d = webtoken.paseto_decode(k, t)
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d == d1 == d2 == b"Hello world!"

            t = webtoken.paseto_encode(k1, b"Hello world!")
            d1 = webtoken.paseto_decode(k1, t)
            d2 = webtoken.paseto_decode(k2, t)
            assert d1 == d2 == b"Hello world!"

            d = webtoken.paseto_decode(k, t)
            assert d == b"Hello world!"



# -- Test Vectors

K4_SECRET_PW = '''
{
  "name": "PASERK k4.secret-pw Test Vectors",
  "tests": [
    {
      "name": "k4.secret-pw-1",
      "unwrapped": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35",
      "password": "correct horse battery staple",
      "options": {"memlimit": 67108864, "opslimit": 2},
      "paserk": "k4.secret-pw.Stkwnh1lHUA7p3t2GDRxdQAAAAAEAAAAAAAAAgAAAAEUtfYRjsLAnE5hGX0Ni8H_W2XdVz5laZ9MdByIYgnDQnXEEx7NyXzBHhKdNVa12XhSLNTNMLuSo5kDMsJUHlEMt8yIE-F7GMDvBXTFvNFniK1Ao0TreYqIYTSKfIvfcZhwiWuHqFGddVhOvTrNt8zi53IeF-g089U"
    },
    {
      "name": "k4.secret-pw-2",
      "unwrapped": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35",
      "password": "correct horse battery staple",
      "options": {"memlimit": 268435456, "opslimit": 3},
      "paserk": "k4.secret-pw.8SqqKhga2erPtJdHMtSD3QAAAAAQAAAAAAAAAwAAAAFgsqMCqzX86kHsjfVlP05h7FBHA-438QAYiiTY4IhpGLDnZLmxLrB4A6P_cC_o2zZR_kxzf5NgsmrsAe-FgrI4e0zd2FhVC3G9d6huc8aKqe-wcUSTLpQsCFTnkuVHM2_sIXQaPoKQl14g-ZjmGEMjtVXiDX6Tb2k"
    }
  ]
}
'''

K4_SEAL = '''
{
  "name": "PASERK k4.seal Test Vectors",
  "tests": [
    {
      "name": "k4.seal-1",
      "sealing-secret-key": "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023",
      "sealing-public-key": "b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023",
      "unsealed": "0000000000000000000000000000000000000000000000000000000000000000",
      "paserk": "k4.seal.OPFn-AEUsKUWtAUZrutVvd9YaZ4CmV4_lk6ii8N72l5gTnl8RlL_zRFqWTZZV9gSnPzARQ_QklrZ2Qs6cJGKOENNOnsDXL5haXcr-QbTXgoLVBvT4ruJ8MdjWXGRTVc9"
    },
    {
      "name": "k4.seal-2",
      "sealing-secret-key": "a770cf90f55d8a6dec51190eb640cb25ce31f7e5eb87a00ca9859022e6da9518a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7",
      "sealing-public-key": "a0fbc3dc2f99a538b40fb7616a83cf4276b6cf223fff5a2c2d3236235eb87dc7",
      "unsealed": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "paserk": "k4.seal.3-VOL4pX5b7eV3uMhYHfOhJNN77YyYtd7wYXrH9rRucKNmq0aO-6AWIFU4xOXUCBk0mzBZeWAPAKrvejqixqeRXm-MQXt8yFGHmM1RzpdJw80nabbyDIsNCpBwltU-uj"
    }
  ]
}
'''

K4_LOCAL_PW = '''
{
  "name": "PASERK k4.local-pw Test Vectors",
  "tests": [
    {
      "name": "k4.local-pw-1",
      "unwrapped": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "password": "correct horse battery staple",
      "options": {"memlimit": 67108864, "opslimit": 2},
      "paserk": "k4.local-pw.-0q-gj9oN18gifSrvpClFwAAAAAEAAAAAAAAAgAAAAH1hyLMFQGs5F1aZoysb7bRtc91SYXu2-bi-mmISIF5cs-SQHp1MoppBFc9I1LTkZA4KsVR_ipH3XdGLj3Pe77qCE64HI1cPG1LNDF0vINnGOrLEaE1Clfi"
    },
    {
      "name": "k4.local-pw-2",
      "unwrapped": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "password": "correct horse battery staple",
      "options": {"memlimit": 268435456, "opslimit": 3},
      "paserk": "k4.local-pw.3oPc6UhC5SCQjL0sCCeTgQAAAAAQAAAAAAAAAwAAAAHimvu_i1YAd7f8VZSilxXd4gXM-sefO6VyEV7qmuDJXx3xuMcg45tjWQit-wOugj-Q-CzhMGYEFNImI2s0gMA8SZE0d_-HbmRM6MsC0XqzlxWpSI8rTyO-"
    }
  ]
}
'''


K4_SECRET_WRAP_PIE = '''
{
  "name": "PASERK k4.secret-wrap.pie Test Vectors",
  "tests": [
    {
      "name": "k4.secret-wrap.pie-1",
      "unwrapped": "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
      "wrapping-key":"707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.secret-wrap.pie.NC6xj8t0VuK-0KE7Fy6PAKtbQwEFRyQMe39A0ctrkaIcS1zjVgvYTN6cu1AZM7bU2bz-jzKclAWu3Bln6xhSOsUqcQPi6Kw_LtKXLRCeggiuPnaqWfIT4qacjXtXhFvOvDPye21fbWOPuoNM9VppuTzN0LzYDYgNYCPsbWt2n4c"
    },
    {
      "name": "k4.secret-wrap.pie-2",
      "unwrapped": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35",
      "wrapping-key": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "paserk": "k4.secret-wrap.pie.dYA31PP6a-d1Cyk3xt2Dz8kpGSlbpwkG5UyrLcgRspSvq1RUO1UQicQNE3-eXYUYGhXrG9zAVnR93tize-IPtiFEyO70U3bWEXd0uU7asDJQ19I3V2mf5OPIcKQl-TnY0XXtw5DPqY1yEFEbA9WTiDG0I3z6KTWA2z09NWm0OHQ"
    }
  ]
}
'''


K4_LOCAL_WRAP_PIE = '''
{
  "name": "PASERK k4.local-wrap.pie Test Vectors",
  "tests": [
    {
      "name": "k4.local-wrap.pie-1",
      "unwrapped": "0000000000000000000000000000000000000000000000000000000000000000",
      "wrapping-key":"707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.local-wrap.pie.y-PC8Zh6P1DoOBUdhRr7W8GWSgHtRKvE8PWWYA-qXy3fxJDmaRsxcZVQzuvXHZuBg5MqCgh_y5K0WbukJCrDX73Wdf631VBnE1DNHafbjnGNzFNWP59ba9ifsOAgE7Bw"
    },
    {
      "name": "k4.local-wrap.pie-2",
      "unwrapped": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "wrapping-key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.local-wrap.pie.cy-Mu6zSfhu6q0_XdAM9p1zre_joUWjreSjHgisVNh-oHaNarN4_c7xuSyaHwqEDxF7lTbfNplBGU7wTeUyt__hZyj1J38NdNxVwuXamJY2QhRE-kWYA9_16xTsGwCQX"
    }
  ]
}
'''

K4_LID = '''
{
  "name": "PASERK k4.lid Test Vectors",
  "tests": [
    {
      "name": "k4.lid-1",
      "key": "0000000000000000000000000000000000000000000000000000000000000000",
      "paserk": "k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"
    },
    {
      "name": "k4.lid-2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.lid.iVtYQDjr5gEijCSjJC3fQaJm7nCeQSeaty0Jixy8dbsk"
    },
    {
      "name": "k4.lid-3",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90",
      "paserk": "k4.lid.-v0wjDR1FVxNT2to41Ay1P4_8X6HIxnybX1nZ1a4FCTm"
    }
  ]
}
'''

K4_SID = '''
{
  "name": "PASERK k4.sid Test Vectors",
  "tests": [
    {
      "name": "k4.sid-1",
      "key": "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
      "seed": "0000000000000000000000000000000000000000000000000000000000000000",
      "paserk": "k4.sid.YujQ-NvcGquQ0Q-arRf8iYEcXiSOKg2Vk5az-n1lxiUd"
    },
    {
      "name": "k4.sid-2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35",
      "seed": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.sid.gHYyx8y5YzqKEZeYoMDqUOKejdSnY_AWhYZiSCMjR1V5"
    },
    {
      "name": "k4.sid-3",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e9060fe37571a5d6e7d30b15154ce4a9fb92c70c870848f4ccdf1626588097f73f7",
      "seed": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90",
      "paserk": "k4.sid.2_m4h6ZTO3qm_PIpl-eYyAqTbNTgmIPQ85POmUEyZHNd"
    }
  ]
}
'''


K4_PID = '''
{
  "name": "PASERK k4.pid Test Vectors",
  "tests": [
    {
      "name": "k4.pid-1",
      "key": "0000000000000000000000000000000000000000000000000000000000000000",
      "paserk": "k4.pid.S_XQmeEwHbbvRmiyfXfHYpLGjXGzjTRSDoT1YtTakWFE"
    },
    {
      "name": "k4.pid-2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs"
    },
    {
      "name": "k4.pid-3",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90",
      "paserk": "k4.pid.-nyvbaTz8U6TQz7OZWW-iB3va31iAxIpUgzUcVQVmW9A"
    }
  ]
}
'''


K4_LOCAL = '''
{
  "name": "PASERK k4.local Test Vectors",
  "tests": [
    {
      "name": "k4.local-1",
      "key": "0000000000000000000000000000000000000000000000000000000000000000",
      "paserk": "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    {
      "name": "k4.local-2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8"
    },
    {
      "name": "k4.local-3",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90",
      "paserk": "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjpA"
    }
  ]
}
'''

K4_SECRET = '''
{
  "name": "PASERK k4.secret Test Vectors",
  "tests": [
    {
      "name": "k4.secret-1",
      "key": "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
      "secret-key-seed": "0000000000000000000000000000000000000000000000000000000000000000",
      "public-key": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
      "paserk": "k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ"
    },
    {
      "name": "k4.secret-2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35",
      "secret-key-seed": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "public-key": "1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35",
      "paserk": "k4.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ"
    },
    {
      "name": "k4.secret-3",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e9060fe37571a5d6e7d30b15154ce4a9fb92c70c870848f4ccdf1626588097f73f7",
      "secret-key-seed": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90",
      "public-key": "60fe37571a5d6e7d30b15154ce4a9fb92c70c870848f4ccdf1626588097f73f7",
      "paserk": "k4.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjpBg_jdXGl1ufTCxUVTOSp-5LHDIcISPTM3xYmWICX9z9w"
    }
  ]
}
'''


K4_PUBLIC = '''
{
  "name": "PASERK k4.public Test Vectors",
  "tests": [
    {
      "name": "k4.public-1",
      "key": "0000000000000000000000000000000000000000000000000000000000000000",
      "paserk": "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    {
      "name": "k4.public-2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "paserk": "k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8"
    },
    {
      "name": "k4.public-3",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90",
      "paserk": "k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjpA"
    }
  ]
}
'''



V4 = '''
{
  "name": "PASETO v4 Test Vectors",
  "tests": [
    {
      "name": "4-E-1",
      "expect-fail": false,
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "nonce": "0000000000000000000000000000000000000000000000000000000000000000",
      "token": "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg",
      "payload": "{\\"data\\": \\"this is a secret message\\", \\"exp\\": \\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "",
      "implicit-assertion": ""
    },
    {
      "name": "4-E-2",
      "expect-fail": false,
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "nonce": "0000000000000000000000000000000000000000000000000000000000000000",
      "token": "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A",
      "payload": "{\\"data\\":\\"this is a hidden message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "",
      "implicit-assertion": ""
    },
    {
      "name": "4-E-3",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA",
      "payload": "{\\"data\\":\\"this is a secret message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "",
      "implicit-assertion": ""
    },
    {
      "name": "4-E-4",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ",
      "payload": "{\\"data\\":\\"this is a hidden message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "",
      "implicit-assertion": ""
    },
    {
      "name": "4-E-5",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a secret message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": ""
    },
    {
      "name": "4-E-6",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a hidden message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": ""
    },
    {
      "name": "4-E-7",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a secret message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": "{\\"test-vector\\":\\"4-E-7\\"}"
    },
    {
      "name": "4-E-8",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a hidden message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": "{\\"test-vector\\":\\"4-E-8\\"}"
    },
    {
      "name": "4-E-9",
      "expect-fail": false,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
      "payload": "{\\"data\\":\\"this is a hidden message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "arbitrary-string-that-isn't-json",
      "implicit-assertion": "{\\"test-vector\\":\\"4-E-9\\"}"
    },
    {
      "name": "4-S-1",
      "expect-fail": false,
      "public-key": "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key-seed": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
      "secret-key-pem": "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\\n-----END PRIVATE KEY-----",
      "public-key-pem": "-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\\n-----END PUBLIC KEY-----",
      "token": "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
      "payload": "{\\"data\\":\\"this is a signed message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "",
      "implicit-assertion": ""
    },
    {
      "name": "4-S-2",
      "expect-fail": false,
      "public-key": "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key-seed": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
      "secret-key-pem": "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\\n-----END PRIVATE KEY-----",
      "public-key-pem": "-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\\n-----END PUBLIC KEY-----",
      "token": "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a signed message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": ""
    },
    {
      "name": "4-S-3",
      "expect-fail": false,
      "public-key": "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key-seed": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
      "secret-key-pem": "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\\n-----END PRIVATE KEY-----",
      "public-key-pem": "-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\\n-----END PUBLIC KEY-----",
      "token": "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a signed message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": "{\\"test-vector\\":\\"4-S-3\\"}"
    },
    {
      "name": "4-F-1",
      "expect-fail": true,
      "public-key": "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key-seed": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
      "secret-key-pem": "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\\n-----END PRIVATE KEY-----",
      "public-key-pem": "-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\\n-----END PUBLIC KEY-----",
      "token": "v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlNdGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
      "payload": null,
      "footer": "arbitrary-string-that-isn't-json",
      "implicit-assertion": "{\\"test-vector\\":\\"4-F-1\\"}"
    },
    {
      "name": "4-F-2",
      "expect-fail": true,
      "nonce": "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v4.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn22Sp4gjCaUw0c7EH84ZSm_jN_Qr41MrgLNu5LIBCzUr1pn3Z-Wukg9h3ceplWigpoHaTLcwxj0NsI1vjTh67YB.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": null,
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": "{\\"test-vector\\":\\"4-F-2\\"}"
    },
    {
      "name": "4-F-3",
      "expect-fail": true,
      "nonce": "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "token": "v3.local.23e_2PiqpQBPvRFKzB0zHhjmxK3sKo2grFZRRLM-U7L0a8uHxuF9RlVz3Ic6WmdUUWTxCaYycwWV1yM8gKbZB2JhygDMKvHQ7eBf8GtF0r3K0Q_gF1PXOxcOgztak1eD1dPe9rLVMSgR0nHJXeIGYVuVrVoLWQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
      "payload": null,
      "footer": "arbitrary-string-that-isn't-json",
      "implicit-assertion": "{\\"test-vector\\":\\"4-F-3\\"}"
    }
  ]
}
'''

