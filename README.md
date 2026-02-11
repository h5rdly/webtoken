![Python Version](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-darkgreen?style=flat&logo=python&logoColor=blue)

# webtoken

**Rust-backed JWT**

##  Size

The `.so` size on linux is ~3.5Mb, no external dependencies.

##  Speed

[Simple benchmark](https://github.com/h5rdly/toke/blob/main/benchmarks/benchmarks.py)

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

- Developed on Linux / Python 3.13
- Tested on Linux (+ Alpine) / Windows / MacOS / FreeBSD
- Wheels available for Linux (+ Alpine) / Windows / MacOS 

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

The rust based encode/decode release the GIL.

You can send them away on asyncio.to_thread(), or use the provided wrappers.

```python
import webtoken as wt

payload = {"name": "Bob"}
token = await wt.encode_async(payload, "secret", algorithm="HS256")

decoded = await wt.decode_async(token, "secret", algorithms=["HS256"])
print(decoded)
# {'name': 'Bob'}
```
#### Crypto / base64 complementary utils

Since webtoken already has aws-lc-rs in its standalone module, it exposes several auxiliary utilities.

This, for example, allows running tests, such as the PyJWT ported test suites, without importing cryptography.

```python
import webtoken as wt


wt.base64url_encode('bob')    # utf8 strings or bytes
# b'Ym9i'

wt.base64url_decode(b'Ym9i').decode()
# 'bob'

rand_7 = wt.random_bytes(7)       # Get your cryptographically secure random bytes here 

priv, pub = wt.generate_key_pair('rs256')  
```

##  Compatibility

Effort is made to make toke as compatible as possible with [PyJWT](https://github.com/jpadilla/pyjwt). For compatibility details, See the readme under [tests](https://github.com/h5rdly/webtoken/tree/main/tests). 

##  Crypto

The crypto backend used by webtoken is [aws-lc-rs](https://github.com/aws/aws-lc-rs).


### Supported algorithms

PyJWT compat - 
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512-
- ES512

Also - 
- ES256K
- ML-DSA-65

