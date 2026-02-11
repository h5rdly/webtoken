import sys
sys.path.append(__file__.replace('\\', '/').rsplit("/", 2)[0])

import webtoken as wt
# from webtoken.exceptions import MissingRequiredClaimError


def test_missing_required_claim_error_has_proper_str():

    exc = wt.MissingRequiredClaimError("abc")
    assert str(exc) == 'Token is missing the "abc" claim'


if __name__ == "__main__":
    test_missing_required_claim_error_has_proper_str()