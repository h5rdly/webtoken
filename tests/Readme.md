## Tests

The major [PyJWT test suites](https://github.com/jpadilla/pyjwt/tree/master/tests) were ported - 
- test_api_jwt.py
- test_api_jws.py
- test_api_jwk.py
- test_algorithms.py

as well as most smaller independent tests (e.g compressed token test).

Porting included - 
- Using internal aws-lc-rs based crypto helper utilitites (eg `generate_key_pair()`) instead of cryptography.
- Using internal Rust based base64 utils.
- Inlining test keys and key data
- removing `@crypto` / `@no_crypto` test tags (There's always crypto, it's kind of our thing)


The tests might be ported to `unittest`, as aside for pytest, there are no external Python dependencies used by webtoken.

