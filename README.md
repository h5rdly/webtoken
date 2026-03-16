![Python](https://img.shields.io/badge/Python-3.12%20%E2%80%93%203.14(t)-darkgreen?logo=python&logoColor=blue)
[![Tests](https://github.com/h5rdly/webtoken/actions/workflows/tests.yml/badge.svg)](https://github.com/h5rdly/webtoken/actions/workflows/tests.yml)

# webtoken

**Rust-backed JWT**

##  Size

The `.so` size on linux is ~`3.9Mb`, no external dependencies.

Simple RAM usage [benchmark](https://github.com/h5rdly/webtoken/blob/main/benchmarks/mem_benchmark.py) -

```
RAM Footprint on Import (Native Linux /proc/self/status):

jwt:         17.54 MB
webtoken:    5.14 MB
```

##  Speed

[Simple benchmark](https://github.com/h5rdly/toke/blob/main/benchmarks/benchmarks.py) comparison to PyJWT

```
HS256
Enc: 2.1x | Dec: 1.5x

RS256
Enc: 54.4x | Dec: 1.3x

ES256
Enc: 1.9x | Dec: 1.4x

EdDSA
Enc: 2.9x | Dec: 2.5x

ES512
Enc: 1.9x | Dec: 1.5x
```

More under [benchmarks](https://github.com/h5rdly/toke/blob/main/benchmarks/).

##  Installation

`pip install webtoken`

- Developed on Linux / Python 3.14
- Tests are run on and wheels are available for Linux (+ Alpine) / Windows / MacOS / FreeBSD

##  Usage

#### PyJWT Style (Drop-in Replacement)

```python
import webtoken as jwt

key = "secret"
payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
token = jwt.encode(payload, key, algorithm="HS256")

decoded = jwt.decode(token, key, algorithms=["HS256"])
print(decoded)
# {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
```

#### Asyncio variants

- The rust based encode/decode release the GIL

- Send them away on asyncio.to_thread(), or use the provided wrappers

```python
import webtoken as wt

payload = {"name": "Bob"}
token = await wt.encode_async(payload, "secret", algorithm="HS256")

decoded = await wt.decode_async(token, "secret", algorithms=["HS256"])
print(decoded)
# {'name': 'Bob'}
```
#### Crypto / base64 complementary utils

- Since webtoken already has `aws-lc-rs` in its standalone module, it exposes several auxiliary utilities

- This, for example, allows running tests, such as the PyJWT ported test suites, without importing cryptography

```python
import webtoken as wt


wt.base64url_encode('bob')    # utf8 strings or bytes
# b'Ym9i'

wt.base64url_decode(b'Ym9i').decode()
# 'bob'

rand_7 = wt.random_bytes(7)       # Get your cryptographically secure random bytes here 

priv, pub = wt.generate_key_pair('rs256')  

verifier, challenge = wt.generate_pkce_pair()
```

##  Compatibility

Effort is made to make toke as compatible as possible with [PyJWT](https://github.com/jpadilla/pyjwt). For compatibility details, See the readme under [tests](https://github.com/h5rdly/webtoken/tree/main/tests). 

##  Crypto

The crypto backend is mostly based on [aws-lc-rs](https://github.com/aws/aws-lc-rs).

XChaCha20 support, for PASETO v4 and JWE, comes via [Graviola](https://github.com/ctz/graviola).
