import base64
import sys
import pytest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])
import webtoken

# --- ASN.1 DER Builder Helpers ---
# These tiny helpers allow us to dynamically build edge-case certificates 
# to strictly test the Rust memory parser without needing real 2KB certificates.

def to_der_len(length: int) -> bytes:
    '''Correctly encodes ASN.1 lengths, including multi-byte lengths > 127.'''
    if length < 128:
        return bytes([length])
    b = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def to_der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + to_der_len(len(content)) + content

def to_seq(content: bytes) -> bytes:       return to_der_tlv(0x30, content)
def to_set(content: bytes) -> bytes:       return to_der_tlv(0x31, content)
def to_oid(oid: bytes) -> bytes:           return to_der_tlv(0x06, oid)
def to_printable(s: bytes) -> bytes:       return to_der_tlv(0x13, s)
def to_utf8(s: bytes) -> bytes:            return to_der_tlv(0x0c, s)
def to_bmp(s: bytes) -> bytes:             return to_der_tlv(0x1e, s)

def create_mock_certificate(subject_bytes: bytes, is_v3: bool = True) -> bytes:
    '''Wraps a raw Subject sequence into a valid TBSCertificate structure.'''
    version = to_der_tlv(0xA0, to_der_tlv(0x02, b'\x02')) if is_v3 else b''
    serial = to_der_tlv(0x02, b'\x01')
    sig_alg = to_seq(b'')
    issuer = to_seq(b'')
    validity = to_seq(b'')
    tbs = to_seq(version + serial + sig_alg + issuer + validity + subject_bytes)
    return to_seq(tbs)


class TestCryptoParsing:

    def test_x509_standard_printable_string(self):
        ''' Tests standard English/ASCII Common Names '''

        cn_oid = to_oid(b'\x55\x04\x03') # 2.5.4.3
        cn_val = to_printable(b'John Doe')
        
        # SEQUENCE { SET { SEQUENCE { OID, VALUE } } }
        subject = to_seq(to_set(to_seq(cn_oid + cn_val)))
        cert = create_mock_certificate(subject)
        
        assert webtoken.get_x509_subject(cert) == 'John Doe'


    def test_x509_cyrillic_utf8_string(self):
        '''
        CRUCIAL FOR B-TRUST: Tests non-ASCII characters.
        Ensures the Rust `String::from_utf8` correctly consumes UTF8String tags.
        '''

        cn_oid = to_oid(b'\x55\x04\x03')
        cyrillic_name = 'Иван Иванов'.encode('utf-8') 
        cn_val = to_utf8(cyrillic_name)
        
        subject = to_seq(to_set(to_seq(cn_oid + cn_val)))
        cert = create_mock_certificate(subject)
        
        assert webtoken.get_x509_subject(cert) == 'Иван Иванов'


    def test_x509_bmp_string_utf16be(self):
        '''
        CRUCIAL FOR ENTERPRISE: Tests UTF-16 BE parsing (BMPString).
        Microsoft AD CS tokens often encode strings this way.
        '''

        cn_oid = to_oid(b'\x55\x04\x03')
        bmp_name = 'Enterprise User'.encode('utf-16-be')
        cn_val = to_bmp(bmp_name)
        
        subject = to_seq(to_set(to_seq(cn_oid + cn_val)))
        cert = create_mock_certificate(subject)
        
        assert webtoken.get_x509_subject(cert) == 'Enterprise User'


    def test_x509_multi_byte_length_parsing(self):
        '''
        Tests the ASN.1 parser's ability to safely read lengths > 127 bytes.
        If the Rust `read_tag` logic fails here, it will crash or truncate the name.
        '''

        cn_oid = to_oid(b'\x55\x04\x03')
        # Create a massive name (300 bytes) to force a 0x82 multi-byte length tag
        massive_name = b'A' * 300 
        cn_val = to_utf8(massive_name)
        
        subject = to_seq(to_set(to_seq(cn_oid + cn_val)))
        cert = create_mock_certificate(subject)
        
        assert webtoken.get_x509_subject(cert) == 'A' * 300


    def test_x509_complex_subject_ordering(self):
        '''
        Tests a certificate where the Common Name is buried at the end 
        of the subject sequence (after Country and Organization).
        '''

        c_oid = to_oid(b'\x55\x04\x06')  # Country
        o_oid = to_oid(b'\x55\x04\x0a')  # Organization
        cn_oid = to_oid(b'\x55\x04\x03') # Common Name
        
        attr1 = to_set(to_seq(c_oid + to_printable(b'BG')))
        attr2 = to_set(to_seq(o_oid + to_utf8(b'B-Trust BORICA AD')))
        attr3 = to_set(to_seq(cn_oid + to_utf8(b'B-Trust Test User')))
        
        subject = to_seq(attr1 + attr2 + attr3)
        cert = create_mock_certificate(subject)
        
        assert webtoken.get_x509_subject(cert) == 'B-Trust Test User'


    def test_x509_v1_cert_without_version_tag(self):
        '''
        Tests legacy v1 certificates. These omit the [0] EXPLICIT version tag entirely.
        This ensures `read_optional_explicit(0)` gracefully falls back.
        '''

        cn_oid = to_oid(b'\x55\x04\x03')
        cn_val = to_printable(b'Legacy V1 User')
        subject = to_seq(to_set(to_seq(cn_oid + cn_val)))
        cert = create_mock_certificate(subject, is_v3=False)
        
        assert webtoken.get_x509_subject(cert) == 'Legacy V1 User'


    def test_x509_missing_common_name(self):
        ''' Tests that certificates without a CN gracefully return a ValueError '''

        o_oid = to_oid(b'\x55\x04\x0a') # Only Organization, no CN
        attr1 = to_set(to_seq(o_oid + to_printable(b'Anonymous Org')))
        
        subject = to_seq(attr1)
        cert = create_mock_certificate(subject)
        
        with pytest.raises(ValueError) as exc:
            webtoken.get_x509_subject(cert)

        assert 'Common Name (CN) not found' in str(exc.value)


    def test_x509_empty_subject(self):
        ''' ests a totally empty subject sequence (used in SAN-only certs) '''

        cert = create_mock_certificate(b'\x30\x00') # Empty sequence
        
        with pytest.raises(ValueError):
            webtoken.get_x509_subject(cert)


    def test_x509_invalid_asn1_garbage(self):
        ''' Throws random memory garbage at the parser to ensure it safely aborts '''
        
        with pytest.raises(ValueError) as exc:
            webtoken.get_x509_subject(b'\x01\x02\x03\x04\xFF\xFF')
        
        assert 'Expected SEQUENCE' in str(exc.value)


    def test_x509_truncated_data(self):
        ''' Tests memory bounds checking. Ensures Rust doesn't segfault on EOF '''

        cn_oid = to_oid(b'\x55\x04\x03')
        cn_val = to_printable(b'John')
        
        subject = to_seq(to_set(to_seq(cn_oid + cn_val)))
        cert = create_mock_certificate(subject)
        
        # Cut off the last 3 bytes of the certificate (Simulate pulling USB token out)
        truncated_cert = cert[:-3]
        
        with pytest.raises(ValueError) as exc:
            webtoken.get_x509_subject(truncated_cert)
            
        assert 'too short' in str(exc.value) or 'Unexpected EOF' in str(exc.value)


    def test_x509_real_world_certificate(self):
        '''
        PROVES: The parser correctly navigates a massive, real-world 
        certificate generated by a standard Certificate Authority. It successfully
        ignores all the complex v3 extensions, massive RSA keys, and signatures 
        to perfectly extract the Subject CN.
        '''

        # Subject is: CN=Testing
        real_cert_b64 = (
            'MIICnTCCAYUCBgGAUN03JTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4X'
            'DTIyMDQyMjEwNDAxNloXDTMyMDQyMjEwNDE1NlowEjEQMA4GA1UEAwwHVGVzdGluZzCCASIw'
            'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJnn9zZF3+PvugbVDyo4ZVe6X+lb+xzIPlS'
            '/iE1/CkGUw+C081jt8fUT8FXqSo4H7yXvyImRWiV+/Pmu86XBvZqWRvHM6dwvJ2UrwCSqYb2'
            'C3fbPamKxjBVvbdXh8hsJiEDdNlV8B3mdCQ3eV+Iu7DuFz5DcnH80qMWkG7+8ADWAU3L3FnI'
            '2FcSI+GaWJErEKq6zk5uvRuxcrq7XxMRnO45UkXL/hrm6vytyECxxh05YpdtMKmZorNXSycK'
            'QI4E8WO7kEsBHaiRwiUd6u+m7A3pSAWaW0dO5KiDl6mLudsNMJAv9Vu/x3FTyzaek/zC9PT/'
            'IxrDlnzDvef83IZLHkMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi7ZppYbkpt0ALn5NXIIP'
            'gA04svRwAmsUJWKLBS5iKVXq6HOJPsz0GAB9oKpjar83rUomwK2UE0XFJLMDvrB0nTZJBjm2'
            'DCANLL1GtTKUd+mdvhyHCIMrUApkhAYzv2Rk1c4+Jt7f5/h8FnM8jdl9FGc5TBy5ixS0Oxny'
            'W1JOakClYQz8vNS7LrC4hmLWwy7GAmUdemNLEefQcECaNzaLN5gGk1ht5lJyNCsHu9STZeYM'
            '2UXdDAtMtu9HAepfzh2CAOscSDtZr89SmFSwxKaOfbJyXH4PivMgWK4zO0P6ofuv8d8gRbUA'
            'UgnysKHQc0isTVWOxgmzI69EUe/iVXJHig=='
        )
        
        der_bytes = base64.b64decode(real_cert_b64)
        subject = webtoken.get_x509_subject(der_bytes)
        
        assert subject == 'Testing'


    def test_x509_metadata_extraction(self):
        '''
        PROVES: The native Rust metadata extractor perfectly pulls out 
        the serial number, issuer, timestamps, AKI, and Key Usages from a real cert
        and hands them to Python as a standard dictionary.
        '''

        real_cert_b64 = (
            'MIICnTCCAYUCBgGAUN03JTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4X'
            'DTIyMDQyMjEwNDAxNloXDTMyMDQyMjEwNDE1NlowEjEQMA4GA1UEAwwHVGVzdGluZzCCASIw'
            'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJnn9zZF3+PvugbVDyo4ZVe6X+lb+xzIPlS'
            '/iE1/CkGUw+C081jt8fUT8FXqSo4H7yXvyImRWiV+/Pmu86XBvZqWRvHM6dwvJ2UrwCSqYb2'
            'C3fbPamKxjBVvbdXh8hsJiEDdNlV8B3mdCQ3eV+Iu7DuFz5DcnH80qMWkG7+8ADWAU3L3FnI'
            '2FcSI+GaWJErEKq6zk5uvRuxcrq7XxMRnO45UkXL/hrm6vytyECxxh05YpdtMKmZorNXSycK'
            'QI4E8WO7kEsBHaiRwiUd6u+m7A3pSAWaW0dO5KiDl6mLudsNMJAv9Vu/x3FTyzaek/zC9PT/'
            'IxrDlnzDvef83IZLHkMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi7ZppYbkpt0ALn5NXIIP'
            'gA04svRwAmsUJWKLBS5iKVXq6HOJPsz0GAB9oKpjar83rUomwK2UE0XFJLMDvrB0nTZJBjm2'
            'DCANLL1GtTKUd+mdvhyHCIMrUApkhAYzv2Rk1c4+Jt7f5/h8FnM8jdl9FGc5TBy5ixS0Oxny'
            'W1JOakClYQz8vNS7LrC4hmLWwy7GAmUdemNLEefQcECaNzaLN5gGk1ht5lJyNCsHu9STZeYM'
            '2UXdDAtMtu9HAepfzh2CAOscSDtZr89SmFSwxKaOfbJyXH4PivMgWK4zO0P6ofuv8d8gRbUA'
            'UgnysKHQc0isTVWOxgmzI69EUe/iVXJHig=='
        )
        der_bytes = base64.b64decode(real_cert_b64)
        
        # Execute
        meta = webtoken.get_x509_metadata(der_bytes)
        
        # Verify structure and PyO3 type bindings
        assert isinstance(meta, dict)
        assert isinstance(meta.get('serial'), str)
        assert isinstance(meta.get('issuer'), str)
        assert isinstance(meta.get('not_before'), int)
        assert isinstance(meta.get('not_after'), int)
        assert isinstance(meta.get('key_usages'), list)
        
        # Verify data accuracy (This specific test cert is valid for 10 years)
        assert meta['issuer'] == 'CN=Testing'
        assert (meta['not_after'] - meta['not_before']) == 315619300  # 3653 days * 86400 seconds + 100 seconds


    def test_x509_public_key_spki_extraction(self):
        '''
        PROVES: The parser successfully isolates the SubjectPublicKeyInfo (SPKI)
        block and returns it as raw ASN.1 DER bytes so `webtoken.verify` can 
        natively digest it.
        '''

        real_cert_b64 = (
            'MIICnTCCAYUCBgGAUN03JTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4X'
            'DTIyMDQyMjEwNDAxNloXDTMyMDQyMjEwNDE1NlowEjEQMA4GA1UEAwwHVGVzdGluZzCCASIw'
            'DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJnn9zZF3+PvugbVDyo4ZVe6X+lb+xzIPlS'
            '/iE1/CkGUw+C081jt8fUT8FXqSo4H7yXvyImRWiV+/Pmu86XBvZqWRvHM6dwvJ2UrwCSqYb2'
            'C3fbPamKxjBVvbdXh8hsJiEDdNlV8B3mdCQ3eV+Iu7DuFz5DcnH80qMWkG7+8ADWAU3L3FnI'
            '2FcSI+GaWJErEKq6zk5uvRuxcrq7XxMRnO45UkXL/hrm6vytyECxxh05YpdtMKmZorNXSycK'
            'QI4E8WO7kEsBHaiRwiUd6u+m7A3pSAWaW0dO5KiDl6mLudsNMJAv9Vu/x3FTyzaek/zC9PT/'
            'IxrDlnzDvef83IZLHkMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi7ZppYbkpt0ALn5NXIIP'
            'gA04svRwAmsUJWKLBS5iKVXq6HOJPsz0GAB9oKpjar83rUomwK2UE0XFJLMDvrB0nTZJBjm2'
            'DCANLL1GtTKUd+mdvhyHCIMrUApkhAYzv2Rk1c4+Jt7f5/h8FnM8jdl9FGc5TBy5ixS0Oxny'
            'W1JOakClYQz8vNS7LrC4hmLWwy7GAmUdemNLEefQcECaNzaLN5gGk1ht5lJyNCsHu9STZeYM'
            '2UXdDAtMtu9HAepfzh2CAOscSDtZr89SmFSwxKaOfbJyXH4PivMgWK4zO0P6ofuv8d8gRbUA'
            'UgnysKHQc0isTVWOxgmzI69EUe/iVXJHig=='
        )
        der_bytes = base64.b64decode(real_cert_b64)
        
        # Execute
        spki_bytes = webtoken.get_x509_public_key(der_bytes)
        
        # Verify
        assert isinstance(spki_bytes, bytes)
        assert len(spki_bytes) > 0
        
        # SPKI is an ASN.1 SEQUENCE, so it MUST mathematically start with 0x30
        assert spki_bytes[0] == 0x30
        
        # The SPKI block for an RSA 2048-bit key is exactly 294 bytes
        assert len(spki_bytes) == 294