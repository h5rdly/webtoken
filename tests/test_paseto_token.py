import sys
sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from webtoken import Token, base64url_decode

import pytest


class TestToken:

    def test_token_new(self):

        token = Token.new(b'v4.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8')
        assert token.version == 'v4'
        assert token.purpose == 'local'
        assert token.payload == base64url_decode(
            'WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8'
        )
        assert token.footer == b''


    def test_token_new_with_str(self):

        token = Token.new(
            'v4.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8'
        )
        assert token.version == 'v4'
        assert token.purpose == 'local'
        assert token.payload == base64url_decode(
            'WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8'
        )
        assert token.footer == b''


    def test_token_setter_payload(self):

        token = Token.new(b'v4.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8')
        token.payload = b'updated-payload'
        assert token.payload == b'updated-payload'


    def test_token_setter_footer(self):

        token = Token.new(b'v4.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8')
        token.footer = b'updated-footer'

        assert token.footer == b'updated-footer'


    @pytest.mark.parametrize(
        'token, msg',
        [
            ('v4', 'token is invalid'),
            ('v4.', 'token is invalid'),
            ('v4.local', 'token is invalid'),
            ('v4.local.', 'Empty payload'),
            ('v4.local.p.f.x', 'token is invalid'),
            ('v4.local.p.f.x.y', 'token is invalid'),
        ],
    )
    def test_token_new_with_invalid_token(self, token, msg):

        with pytest.raises(ValueError) as err:
            Token.new(token)

        assert msg in str(err.value)