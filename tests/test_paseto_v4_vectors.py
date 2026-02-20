import pytest
import json
import webtoken

# --- Tests ---

class TestV4Vectors:
    def test_v4_vectors(self):
        vectors = json.loads(VECTORS_V4_JSON)["tests"]
        for vector in vectors:
            name = vector["name"]
            
            payload_dict = json.loads(vector["payload"]) 
            footer = vector["footer"].encode("utf-8") if vector["footer"] else None
            implicit = vector["implicit-assertion"].encode("utf-8") if vector["implicit-assertion"] else None
            
            mode = name.split("-")[1]

            if mode == "E":
                key = bytes.fromhex(vector["key"])
                nonce = bytes.fromhex(vector["nonce"])
                expected_token = vector["token"]

                token = webtoken.paseto_encode(
                    key, 
                    payload_dict, 
                    purpose="local", 
                    footer=footer, 
                    implicit_assertion=implicit,
                    nonce=nonce
                )
                assert token == expected_token, f"Encryption failed for {name}"

                decoded = webtoken.paseto_decode(
                    key, 
                    expected_token, 
                    purpose="local", 
                    implicit_assertion=implicit
                )
                assert decoded == payload_dict, f"Decryption failed for {name}"

            elif mode == "S":
                secret_key_bytes = bytes.fromhex(vector["secret-key"])[:32] 
                public_key_bytes = bytes.fromhex(vector["public-key"])
                expected_token = vector["token"]

                token = webtoken.paseto_encode(
                    secret_key_bytes,
                    payload_dict,
                    purpose="public",
                    footer=footer,
                    implicit_assertion=implicit
                )
                assert token == expected_token, f"Signing failed for {name}"

                decoded = webtoken.paseto_decode(
                    public_key_bytes,
                    expected_token,
                    purpose="public",
                    implicit_assertion=implicit
                )
                assert decoded == payload_dict, f"Verification failed for {name}"

class TestPaserkVectors:
    def test_paserk_vectors(self):
        for vector in PASERK_VECTORS:
            name = vector["name"]
            expected_paserk = vector["paserk"]

            # 1. Advanced Cryptographic Unwrapping Tests
            if "unwrapped" in vector or "unsealed" in vector:
                if ".local-wrap.pie" in name or ".secret-wrap.pie" in name:
                    expected_unwrapped = bytes.fromhex(vector["unwrapped"])
                    wrapping_key = bytes.fromhex(vector["wrapping-key"])
                    unwrapped = webtoken.paserk_unwrap(expected_paserk, wrapping_key=wrapping_key)
                    assert unwrapped == expected_unwrapped, f"PIE Unwrapping failed for {name}"
                
                elif ".local-pw" in name or ".secret-pw" in name:
                    expected_unwrapped = bytes.fromhex(vector["unwrapped"])
                    password = vector["password"].encode("utf-8")
                    unwrapped = webtoken.paserk_unwrap(expected_paserk, password=password)
                    assert unwrapped == expected_unwrapped, f"PBKW Unwrapping failed for {name}"
                
                elif ".seal" in name:
                    expected_unwrapped = bytes.fromhex(vector["unsealed"])
                    unsealing_key = bytes.fromhex(vector["sealing-secret-key"])
                    unwrapped = webtoken.paserk_unwrap(expected_paserk, unsealing_key=unsealing_key)
                    assert unwrapped == expected_unwrapped, f"Sealing Unwrapping failed for {name}"
            
            # 2. Basic Serialization & ID Tests
            else:
                raw_key = bytes.fromhex(vector["key"])
                if ".pid" in name or ".sid" in name or ".lid" in name:
                    purpose_map = {"pid": "public", "sid": "secret", "lid": "local"}
                    short_type = name.split(".")[1].split("-")[0]
                    purpose = purpose_map[short_type]
                    result = webtoken.paserk_id(raw_key, purpose)
                    assert result == expected_paserk, f"PASERK ID failed for {name}"
                else:
                    purpose = name.split(".")[1].split("-")[0]
                    result = webtoken.paserk_wrap(raw_key, purpose)
                    assert result == expected_paserk, f"PASERK serialization failed for {name}"

class TestPaserkIntegration:
    def test_paserk_local_integration(self):
        raw_key = bytes.fromhex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
        paserk_key = webtoken.paserk_wrap(raw_key, "local")
        assert paserk_key.startswith("k4.local.")

        payload = {"foo": "bar"}
        token = webtoken.paseto_encode(paserk_key, payload, purpose="local")
        
        decoded = webtoken.paseto_decode(paserk_key, token, purpose="local")
        assert decoded == payload

    def test_paserk_public_integration(self):
        seed = bytes.fromhex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774")
        pub_bytes = bytes.fromhex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")

        secret_paserk = webtoken.paserk_wrap(seed, "secret")
        public_paserk = webtoken.paserk_wrap(pub_bytes, "public")

        payload = {"foo": "bar"}

        token = webtoken.paseto_encode(secret_paserk, payload, purpose="public")
        decoded = webtoken.paseto_decode(public_paserk, token, purpose="public")
        
        assert decoded == payload


# ==============================================================================
# --- Test Data (Official Vectors Inline) ---
# ==============================================================================

VECTORS_V4_JSON = """
{
  "name": "PASETO v4 Test Vectors",
  "tests": [
    {
      "name": "4-E-1",
      "expect-fail": false,
      "key": "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      "nonce": "0000000000000000000000000000000000000000000000000000000000000000",
      "token": "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg",
      "payload": "{\\"data\\":\\"this is a secret message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
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
      "name": "4-S-1",
      "expect-fail": false,
      "public-key": "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
      "secret-key": "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
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
      "token": "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
      "payload": "{\\"data\\":\\"this is a signed message\\",\\"exp\\":\\"2022-01-01T00:00:00+00:00\\"}",
      "footer": "{\\"kid\\":\\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\\"}",
      "implicit-assertion": ""
    }
  ]
}
"""

PASERK_VECTORS = [
    # -------------------------------------------------------------
    # 1. Base Type Serialization & IDs
    # -------------------------------------------------------------
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
        "name": "k4.public-1",
        "key": "0000000000000000000000000000000000000000000000000000000000000000",
        "paserk": "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    {
        "name": "k4.secret-1",
        "key": "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        "paserk": "k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ"
    },
    {
        "name": "k4.pid-1",
        "key": "0000000000000000000000000000000000000000000000000000000000000000",
        "paserk": "k4.pid.S_XQmeEwHbbvRmiyfXfHYpLGjXGzjTRSDoT1YtTakWFE"
    },
    {
        "name": "k4.sid-1",
        "key": "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        "paserk": "k4.sid.YujQ-NvcGquQ0Q-arRf8iYEcXiSOKg2Vk5az-n1lxiUd"
    },
    {
        "name": "k4.lid-1",
        "key": "0000000000000000000000000000000000000000000000000000000000000000",
        "paserk": "k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"
    },

    # -------------------------------------------------------------
    # 2. Platform-Independent Encryption (PIE)
    # -------------------------------------------------------------
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
    },
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
    },

    # -------------------------------------------------------------
    # 3. Password-Based Key Wrapping (PBKW)
    # -------------------------------------------------------------
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
    },
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
    },

    # -------------------------------------------------------------
    # 4. Public Key Sealing (Seal)
    # -------------------------------------------------------------
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