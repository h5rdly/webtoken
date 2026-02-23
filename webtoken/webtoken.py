import os, sys, types, importlib.util, datetime, warnings, json

from collections.abc import Iterable


## -- Moudle loading helpers 

def _load_module(module_name: str, path: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return None


def _load_rust_pip_or_dev(_rust_lib_name: str = '_webtoken', module_dev_path: str = None):

    _dev_path_linux = f'target/release/lib{_rust_lib_name}.so'
    module_dev_path = module_dev_path or _dev_path_linux

    rust_lib = None
    try:
        from . import _webtoken
        rust_lib = _webtoken
    except ImportError:
        pass

    for file in os.listdir(__file__.replace('\\', '/').rsplit('/', 1)[0]):
        if file.startswith(f'lib{_rust_lib_name}') and file.endswith((".so", ".pyd", ".dylib", 'dll')):
            rust_lib = _load_module(_rust_lib_name, f'{py_dir}/{file}')
            break
    else:
        if os.path.exists(module_dev_path):
            rust_lib = _load_module(_rust_lib_name, _dev_path_linux)

    if rust_lib is None:
        raise ImportError("Could not find Rust binary")

    return rust_lib


## -- Rust module loading

rust_lib = _load_rust_pip_or_dev()
globals().update({k: v for k, v in vars(rust_lib).items() if not k.startswith("__")})

# Expose Types
PyJWK = rust_lib.api_jwk.PyJWK
PyJWKError = rust_lib.api_jwk.PyJWKError
PyJWKSetError = rust_lib.api_jwk.PyJWKSetError

_sentinel = object()

class InsecureKeyLengthWarning(UserWarning): pass
class RemovedInPyjwt3Warning(DeprecationWarning):  pass

InvalidKeyError = rust_lib.InvalidKeyError 
rust_lib.InsecureKeyLengthWarning = InsecureKeyLengthWarning
rust_lib.RemovedInPyjwt3Warning = RemovedInPyjwt3Warning


class MissingRequiredClaimError(InvalidTokenError):
    def __init__(self, claim):
        self.claim = claim
        super().__init__(f'Token is missing the "{claim}" claim')


## --  JWT Helpers

def _merge_options(default_options: dict | None, options: dict | None, kwargs: dict) -> dict:

    merged = default_options.copy() if default_options else {}
    if options: merged.update(options)
    if kwargs.get("verify") is False: merged["verify_signature"] = False
    if merged.get("verify_signature") is False:
        for k in ["verify_exp", "verify_nbf", "verify_iat", "verify_aud", "verify_iss", "verify_sub", "verify_jti"]:
            if k not in merged: merged[k] = False
    return merged


def _validate_key_length(key, algorithm, enforce):

    if algorithm.startswith("HS"):
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        
        if isinstance(key_bytes, bytes):
            min_len = {"HS256": 32, "HS384": 48, "HS512": 64}.get(algorithm, 0)
            
            if len(key_bytes) < min_len:
                msg = f"The specified key is {len(key_bytes)} bytes long, which is below the minimum recommended length of {min_len} bytes."
                if enforce:
                    raise rust_lib.InvalidKeyError(msg)
                else:
                    warnings.warn(msg, InsecureKeyLengthWarning)


def _validate_iss(payload, issuer):

    if issuer is None: 
        return

    if "iss" not in payload: 
        raise rust_lib.MissingRequiredClaimError("iss")

    if payload["iss"] != issuer:
        if isinstance(issuer, (list, tuple, set)) and payload["iss"] in issuer: 
            return

        raise rust_lib.InvalidIssuerError("Invalid issuer")


def _rust_decode_with_exception_fix(
    token: str | bytes, key: str | bytes | PyJWK | None, algorithms: list[str] | None,
    merged_options: dict[str, object], audience: str | Iterable[str] | None, issuer: str | None,
    subject: str | None, verify_sig: bool, content: bytes | None, return_dict: bool = True
) -> dict[str, object]:

    try:
        return rust_lib.decode_complete(
            token, key, algorithms, merged_options, audience, issuer, subject, verify_sig, content, return_dict)
    except rust_lib.MissingRequiredClaimError as e:
        if ": " in (msg := str(e)): 
            e.claim = msg.split(": ")[1]
        else:        
            if (start := msg.find('"')) != -1:
                if (end := msg.find('"', start + 1)) != -1:
                    e.claim = msg[start + 1 : end]
        raise e


## -- JWT main logic

def encode(
    payload: dict[str, object] | bytes, 
    key: str | bytes | PyJWK, 
    algorithm: str = "HS256", 
    headers: dict[str, object] | None = None, 
    json_encoder: object = None, 
    sort_headers: bool = True,
    check_length: bool = False
) -> str:
    
    if isinstance(payload, dict) and json_encoder is None:
        return  rust_lib.encode(payload, key, algorithm, headers, sort_headers, check_length)

    if not isinstance(payload, (dict, bytes)):
        raise TypeError("Expecting a dict or bytes object")

    if headers and json_encoder:
        try:
            # Execute the user's encoder 
            headers = json.loads(json.dumps(headers, separators=(",", ":"), cls=json_encoder))
        except Exception as e:
            raise TypeError(f"Header serialization failed: {e}")

    # Custom encoders or raw bytes (PyJWS)
    if isinstance(payload, dict):
        for time_claim in ["exp", "iat", "nbf"]:
            if isinstance((claim := payload.get(time_claim)), datetime.datetime):
                payload[time_claim] = int(claim.replace(tzinfo=datetime.timezone.utc).timestamp())
        
        payload = json.dumps(payload, separators=(",", ":"), cls=json_encoder).encode("utf-8")
    
    return rust_lib.sign(payload, key, algorithm, headers, sort_headers, check_length)


def decode(
    token: str, key: str | bytes | PyJWK = None, algorithms: list[str] = None, 
    options: dict[str, object] = None, **kwargs
) -> dict[str, object]:

    decoded = decode_complete(token, key, algorithms, options, **kwargs)
    return decoded["payload"]


def decode_complete(
    token: str, key: str | bytes | PyJWK = None, algorithms: list[str] | None = None,
    options: dict[str, object] | None = None, audience: str | list[str] = None, 
    issuer: str = None, subject: str = None, verify: object = _sentinel, 
    content: bytes = None, leeway: int | float | datetime.timedelta = 0, **kwargs
) -> dict[str, object]:
    
    merged_options = options.copy() if options else {}
    if verify is not _sentinel:
        # PyJWT compat warning
        warnings.warn("The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer.", DeprecationWarning, stacklevel=2)
        if verify is False: 
            merged_options["verify_signature"] = False
    
    verify_sig = merged_options.get("verify_signature", True)
    merged_options["leeway"] = int(leeway.total_seconds() if isinstance(leeway, datetime.timedelta) else leeway)
    
    decoded_struct = _rust_decode_with_exception_fix(
        token, key, algorithms, merged_options, audience, issuer, subject, verify_sig, content)
    
    return decoded_struct


# --- Async Wrappers 

async def encode_async(
    payload: dict[str, object], 
    key: str | bytes, 
    algorithm: str = "HS256", 
    headers: dict[str, object] | None = None
) -> str:
    return await asyncio.to_thread(encode, payload, key, algorithm, headers)


async def decode_async(
    token: str,
    key: str | bytes,
    algorithms: list[str] | None = None,
    options: dict[str, object] | None = None,
    audience: str | list[str] = None,
    issuer: str = None,
    subject: str = None,
    verify: bool = True,
    content: bytes = None,
) -> dict[str, object]:

    return await asyncio.to_thread(
        decode, token, key, algorithms, options, audience, issuer, subject, verify, content
    )



## -- Wrapper Classes form PyJWT compat

def _enforce_hmac_key_length(algorithm: str, key: str | bytes, raise_on_keylength = False):

    if not algorithm.startswith("HS"):
        return

    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    if not isinstance(key_bytes, bytes):
        return
        
    min_len = {"HS256": 32, "HS384": 48, "HS512": 64}.get(algorithm, 0)
    if (key_len := len(key_bytes)) >= min_len:
        return
        
    msg = f"The specified key is {key_len} bytes long, which is below the minimum recommended length of {min_len} bytes."
    if raise_on_keylength:
        raise rust_lib.InvalidKeyError(msg)
    else:
        warnings.warn(msg, InsecureKeyLengthWarning)


class PyJWT:

    def __init__(self, options=None):
        self.options = {"verify_signature": True, "verify_exp": True, "verify_nbf": True, "verify_iat": True, "verify_aud": True, "verify_iss": True, "verify_sub": True, "verify_jti": True, "require": []}
        if options: self.options.update(options)
    

    def encode(self, payload, key, algorithm="HS256", headers=None, json_encoder=None, sort_headers=True):
        _enforce_hmac_key_length(algorithm, key, raise_on_keylength=True)
        return encode(payload, key, algorithm, headers, json_encoder, sort_headers)
    

    def decode(self, token, key="", algorithms=None, options=None, **kwargs):
        merged = _merge_options(self.options, options, kwargs)
        return decode(token, key, algorithms, merged, **kwargs)
    

    def decode_complete(self, token, key="", algorithms=None, options=None, **kwargs):

        merged = _merge_options(self.options, options, kwargs)

        if hasattr(self, "_decode_payload"):
             decoded_struct = _rust_decode_with_exception_fix(
                token, key, algorithms, merged, None, None, None, merged.get("verify_signature", True), 
                None, return_dict=False) 

             # Pass the raw struct to the custom python decoder
             payload = self._decode_payload(decoded_struct)
             
             # Validate the result of the custom decoder
             rust_lib.validate_claims(payload, merged, **kwargs)
             decoded_struct["payload"] = payload

             return decoded_struct

        return decode_complete(token, key, algorithms, merged, **kwargs)

        
class PyJWS:

    header_typ = "JWT"

    def __init__(self, algorithms=None, options=None):

        self._algorithms = get_default_algorithms()
        self.options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "require": [],
        }
        
        if options:
            if not isinstance(options, dict):
                raise TypeError("options must be a dict")
            self.options.update(options)

        if algorithms:
            allowed = set(algorithms)
            for k in list(self._algorithms.keys()):
                if k not in allowed: del self._algorithms[k]


    def register_algorithm(self, alg_id, alg_obj):
        if alg_id in self._algorithms: raise ValueError("Algorithm already has a handler.")
        if not isinstance(alg_obj, Algorithm): raise TypeError("Object is not of type `Algorithm`")
        self._algorithms[alg_id] = alg_obj
    

    def unregister_algorithm(self, alg_id):
        if alg_id not in self._algorithms: raise KeyError("The specified algorithm could not be removed because it is not registered.")
        del self._algorithms[alg_id]
    

    def get_algorithms(self): return list(self._algorithms.keys())
    

    def get_algorithm_by_name(self, alg_name):
        try: return self._algorithms[alg_name]
        except KeyError: raise NotImplementedError("Algorithm not supported")


    def get_unverified_header(self, token): 
        return rust_lib.get_unverified_header(token)


    def encode(self, payload, key, algorithm="HS256", headers=None, json_encoder=None, is_payload_detached=False, sort_headers=False):
        
        if headers and "alg" in headers: 
            algorithm = headers["alg"]

        if algorithm not in self._algorithms: 
            raise NotImplementedError("Algorithm not supported")
        
        check_len = self.options.get("enforce_minimum_key_length", False)
        _enforce_hmac_key_length(algorithm, key, raise_on_keylength=check_len)

        return encode(payload, key, algorithm, headers, json_encoder, sort_headers, check_length=check_len)
    

    def decode(
        self,
        token: str | bytes,
        key: str | bytes | PyJWK = "",
        algorithms: list[str] | None = None,
        options: dict[str, object] | None = None,
        detached_payload: bytes = None,
        **kwargs: object,
    ) -> dict[str, object] | bytes:
        
        decoded = self.decode_complete(token, key, algorithms, options, detached_payload=detached_payload, **kwargs)
        return decoded["payload"]
    

    def decode_complete(
        self,
        token: str | bytes,
        key: str | bytes | PyJWK = "",
        algorithms: list[str] | None = None,
        options: dict[str, object] | None = None,
        detached_payload: bytes = None,
        **kwargs: object,
    ) -> dict[str, object]:
        
        pyjwt_allowed_kwargs = {"verify", "audience", "issuer", "subject", "leeway"}
        for k in kwargs:
            if k not in pyjwt_allowed_kwargs:
                # To pass PyJWT compat tests, dump at some point
                warnings.warn(
                    f"Argument '{k}' is not supported and will be removed in a future version",
                    category=RemovedInPyjwt3Warning,
                    stacklevel=2,
                )

        merged_ops = self.options.copy()
        if options: merged_ops.update(options)

        verify_sig = merged_ops.get("verify_signature", True)
        
        return _rust_decode_with_exception_fix(
            token, key, algorithms, merged_ops, None, None, None, verify_sig, detached_payload, return_dict=False)
    

# -- Curves shim  

class Curve:
    name: str

class SECP256R1(Curve):
    name = "P-256"

class SECP384R1(Curve):
    name = "P-384"

class SECP521R1(Curve):
    name = "P-521"

class SECP256K1(Curve):
    name = "secp256k1"


# -- Algorithms Shim 

class Algorithm:
    
    def sign(self, msg, key): raise NotImplementedError
    def verify(self, msg, key, sig): raise NotImplementedError
    def check_crypto_key_type(self, key): pass

    def check_key_length(self, key): 
        pass
        
    def prepare_key(self, key):

        if key is None: 
            raise TypeError("Key cannot be None")
        return key


    def compute_hash_digest(self, bytes_data):
        alg = getattr(self, "alg", "SHA256")
        return bytes(rust_lib.digest(alg, bytes_data))


    def _prepare_asymmetric_key(self, key):
        """
        Shared logic for RSA/EC/OKP:
        1. If already PyJWK, return it.
        2. If bytes/str, try to load as PEM -> PyJWK.
        3. If fails, raise error (strict).
        """

        if isinstance(key, PyJWK):
            return key
        
        if isinstance(key, (str, bytes)):
            try:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                # Fast Rust PEM parsing
                json_str = rust_lib.pem_to_jwk(key_bytes)
                return rust_lib.load_jwk(json_str)
            except Exception as e:
                raise rust_lib.InvalidKeyError("Could not parse the provided public key.")
                
        raise TypeError("Key must be PyJWK, bytes, or string")


    def _load_pem_to_pyjwk(self, key):
        """Shared helper to safely load PEM bytes/str into a PyJWK."""

        if isinstance(key, (str, bytes)):
            try:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key
                # Use the Native Rust function directly! 
                # It goes Bytes -> Internal Rust Struct -> PyJWK (No JSON overhead)
                return rust_lib.load_key_from_pem(key_bytes)
            except Exception:
                pass
        return None


    @staticmethod
    def from_jwk(jwk):
        try: 
            return rust_lib.load_jwk(rust_lib.json_dumps(jwk) if isinstance(jwk, dict) else jwk)
        except Exception as e: 
             if "Key type" in str(e): 
                raise rust_lib.InvalidKeyError("Key type (kty) not found") 
             raise rust_lib.InvalidKeyError("Invalid key")
             
    
    def to_jwk(self, key, as_dict=False):

        if isinstance(key, dict): 
            raise rust_lib.InvalidKeyError("Invalid key: dict is not a supported key type for to_jwk")
            
        jwk_data = None

        # 1. Extract data from PyJWK or Object with as_dict
        if isinstance(key, PyJWK):
            jwk_data = key.as_dict()
        elif hasattr(key, "as_dict"):
            jwk_data = key.as_dict()
        else:
            # 2. Fallback: Parse from PEM bytes
            try:
                key_bytes = key if isinstance(key, bytes) else key.encode()
                json_str = rust_lib.pem_to_jwk(key_bytes)
                jwk_data = rust_lib.json_loads(json_str)
            except Exception:
                raise rust_lib.InvalidKeyError("Invalid key")

        # 3. Validate Curve for EC Keys
        if jwk_data.get("kty") == "EC":
            crv = jwk_data.get("crv")
            if crv not in ("P-256", "P-384", "P-521", "secp256k1"):
                raise rust_lib.InvalidKeyError(f"Invalid curve: {crv}")

        if as_dict:
            return jwk_data
        
        return rust_lib.json_dumps(jwk_data)


class NoneAlgorithm(Algorithm):

    def prepare_key(self, key): 
        if key is not None: raise rust_lib.InvalidKeyError("Key must be None for NoneAlgorithm")
        return None
    def sign(self, msg, key): return b""
    def verify(self, msg, key, sig): return True
    def check_crypto_key_type(self, key): raise ValueError("NoneAlgorithm does not support cryptographic keys")
    def to_jwk(self, key, as_dict=False): raise NotImplementedError
    def from_jwk(self, jwk): raise NotImplementedError


class HMACAlgorithm(Algorithm):
    SHA256 = "SHA256"; SHA384 = "SHA384"; SHA512 = "SHA512"
    
    def __init__(self, alg): 
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        # Map hash alg to JWS alg for Rust and Lookups
        self.alg = {
            "SHA256": "HS256",
            "SHA384": "HS384",
            "SHA512": "HS512"
        }.get(self.hash_alg, "HS256")
    
    
    def sign(self, msg, key): 
        return bytes(rust_lib.raw_sign(msg, key, self.alg))

    def verify(self, msg, key, sig): 
        return rust_lib.raw_verify(msg, bytes(sig), key, self.alg)
    

    def check_key_length(self, key):

        if isinstance(key, (str, bytes)):
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            
            req = {"HS256": 32, "HS384": 48, "HS512": 64}.get(self.alg, 0)
            if len(key_bytes) < req: 
                return f"The specified key is {len(key_bytes)} bytes long, which is below the minimum recommended length of {req} bytes."


    @staticmethod
    def from_jwk(jwk):
        key = Algorithm.from_jwk(jwk)
        if key.key_type != "oct": 
            raise rust_lib.InvalidKeyError("Not an HMAC key")
        return key


    def to_jwk(self, key, as_dict=False):

        if isinstance(key, (dict, PyJWK)): 
            return super().to_jwk(key, as_dict)

        if isinstance(key, (str, bytes)):
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            data = {"kty": "oct", "k": rust_lib.base64url_encode(key_bytes).decode("utf-8")}
            return data if as_dict else rust_lib.json_dumps(data)
            
        raise rust_lib.InvalidKeyError("Invalid key type for HMAC JWK generation")


    def prepare_key(self, key):

        if key is None: 
            raise TypeError("Key cannot be None")

        if not isinstance(key, (str, bytes, PyJWK)): 
            raise TypeError("Expected a string value")

        if isinstance(key, (str, bytes)):
            try:
                key_text = key.decode("utf-8") if isinstance(key, bytes) else key
                if "-----BEGIN" in key_text or "ssh-" in key_text:
                    raise rust_lib.InvalidKeyError("The specified key is an asymmetric key...")
            except UnicodeDecodeError:
                # If it's not valid UTF-8, it's likely a binary secret, which is allowed.
                pass

        return key



class RSAAlgorithm(Algorithm):

    SHA256 = "SHA256"; SHA384 = "SHA384"; SHA512 = "SHA512"

    def __init__(self, alg): 
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        # Simple mapping for standard RSA
        self.alg = {
            "SHA256": "RS256",
            "SHA384": "RS384",
            "SHA512": "RS512"
        }.get(self.hash_alg, "RS256")


    def sign(self, msg, key): 
        return bytes(rust_lib.raw_sign(msg, key, self.alg))

    def verify(self, msg, key, sig): 
        return rust_lib.raw_verify(msg, bytes(sig), key, self.alg)
    
    def check_key_length(self, key):
        return rust_lib.check_rsa_key_length(key)


    def to_jwk(self, key, as_dict=False):

        jwk_dict = key.as_dict() if isinstance(key, PyJWK) else super().to_jwk(key, as_dict=True)

        if "key_ops" not in jwk_dict:
            jwk_dict["key_ops"] = ["sign"] if "d" in jwk_dict else ["verify"]

        return jwk_dict if as_dict else rust_lib.json_dumps(jwk_dict)


    @staticmethod
    def from_jwk(jwk):

        key = super(RSAAlgorithm, RSAAlgorithm).from_jwk(jwk)
        if key.key_type != "RSA":
            raise rust_lib.InvalidKeyError("Key must be RSA")
            
        key.validate_rsa_consistency()

        return key
    
    
    def prepare_key(self, key):

        if (jwk := self._prepare_asymmetric_key(key)).key_type != "RSA":
             raise rust_lib.InvalidKeyError(f"Invalid key type: {jwk.key_type}. Expected RSA.")

        return jwk


class RSAPSSAlgorithm(RSAAlgorithm):

    def __init__(self, alg):
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        self.alg = {
            "SHA256": "PS256",
            "SHA384": "PS384",
            "SHA512": "PS512"
        }.get(self.hash_alg, "PS256")


# For PyJWT compatibility when throwing errors
cryptography_curve_names = {"P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1", "P-192": "secp192r1"}

class ECAlgorithm(Algorithm):
    SHA256 = "SHA256"; SHA384 = "SHA384"; SHA512 = "SHA512"
    
    def __init__(self, alg, curve=None): 
        self.hash_alg = alg if isinstance(alg, str) else "SHA256"
        self.alg = {
            "SHA256": "ES256",
            "SHA384": "ES384",
            "SHA512": "ES512"
        }.get(self.hash_alg, "ES256")
        self.expected_curve = curve
    

    def sign(self, msg, key): 

        alg = self.alg
        if isinstance(key, PyJWK) and key.algorithm_name and key.algorithm_name.startswith("ES"):
            alg = key.algorithm_name

        return bytes(rust_lib.raw_sign(msg, key, alg))


    def verify(self, msg, key, sig): 

        alg = self.alg
        if isinstance(key, PyJWK) and key.algorithm_name and key.algorithm_name.startswith("ES"):
            alg = key.algorithm_name

        return rust_lib.raw_verify(msg, bytes(sig), key, alg)


    @staticmethod
    def from_jwk(jwk):

        key = Algorithm.from_jwk(jwk)
        rust_lib.validate_key_properties(key, "EC", None)

        return key


    def prepare_key(self, key):

        jwk = self._prepare_asymmetric_key(key)
        
        expected_name = None
        if self.expected_curve:
            expected_name = getattr(self.expected_curve, "name", None) or str(self.expected_curve)

        rust_lib.validate_key_properties(jwk, "EC", expected_name)
        return jwk


class OKPAlgorithm(Algorithm):

    def sign(self, msg, key): return bytes(rust_lib.raw_sign(msg, key, "EdDSA"))
    def verify(self, msg, key, sig): return rust_lib.raw_verify(msg, bytes(sig), key, "EdDSA")


    @staticmethod
    def from_jwk(jwk):

        key = Algorithm.from_jwk(jwk)
        rust_lib.validate_key_properties(key, "OKP", "Ed25519")
        
        return key


    def prepare_key(self, key):

        try:
            jwk = self._prepare_asymmetric_key(key)
        except TypeError:
            # match PyJWT - OKP tests require InvalidKeyError for bad types 
            raise rust_lib.InvalidKeyError("Key must be PyJWK, bytes, or string")

        rust_lib.validate_key_properties(jwk, "OKP", "Ed25519")
        
        return jwk
        


def get_default_algorithms():

    default_algorithms = {
        "none": NoneAlgorithm(),
        
        "HS256": HMACAlgorithm("SHA256"), "HS384": HMACAlgorithm("SHA384"), "HS512": HMACAlgorithm("SHA512"),
        "RS256": RSAAlgorithm("SHA256"), "RS384": RSAAlgorithm("SHA384"), "RS512": RSAAlgorithm("SHA512"),
        "PS256": RSAAlgorithm("SHA256"), "PS384": RSAAlgorithm("SHA384"), "PS512": RSAAlgorithm("SHA512"),
        
        "ES256": ECAlgorithm("SHA256", SECP256R1), 
        "ES384": ECAlgorithm("SHA384", SECP384R1), 
        "ES512": ECAlgorithm("SHA512", SECP521R1), 
        "ES521": ECAlgorithm("SHA512", SECP521R1),  # Alias to ES512
        "ES256K": ECAlgorithm("SHA256", SECP256K1),
        
        "EdDSA": OKPAlgorithm(),
    }

    return default_algorithms


def from_asymmetric_key_params(x: bytes = b"", y: bytes = b"", d: bytes = b"") -> bytes:
    """
    For compatibility with pyseto v4 style Ed25519 coordinate loading
    """

    if x and d:
        raise ValueError("Only one of x or d should be set for v4.public.")
    if not x and not d:
        raise ValueError("x or d should be set for v4.public.")
        
    if len((key_bytes := d or x)) != 32:
        raise ValueError("Failed to load key")
        
    return key_bytes

## -- Epilogue - module wiring 

sys.modules["webtoken.api_jwk"] = rust_lib.api_jwk

rust_lib.api_jws.PyJWS = PyJWS
sys.modules["webtoken.api_jws"] = rust_lib.api_jws

algs = rust_lib.algorithms
algs.Algorithm = Algorithm
algs.NoneAlgorithm = NoneAlgorithm
algs.HMACAlgorithm = HMACAlgorithm
algs.RSAAlgorithm = RSAAlgorithm
algs.ECAlgorithm = ECAlgorithm
algs.RSAPSSAlgorithm = RSAPSSAlgorithm 
algs.OKPAlgorithm = OKPAlgorithm
algs.get_default_algorithms = get_default_algorithms
sys.modules["webtoken.algorithms"] = algs

curves = types.ModuleType("webtoken.curves")
curves.SECP256R1 = SECP256R1
curves.SECP384R1 = SECP384R1
curves.SECP521R1 = SECP521R1
curves.SECP256K1 = SECP256K1
sys.modules["webtoken.curves"] = curves

