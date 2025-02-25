import jose.exceptions
from jose import jwt
from typing import Union

from . import JWKS, ServiceAuth0Token, ManagementAuth0Token
from settings import config


class AuthException(Exception):
    pass


class AuthenticationFailed(Exception):
    pass


jwks = JWKS(auth0_domain=config.auth0_domain, auth_exception=AuthenticationFailed)


class Auth0Authentication:
    def authenticate_request(
        self,
        invocation_metadata,
        audience: str
    ) -> dict:
        header = self.get_header(invocation_metadata)
        if header is None:
            raise AuthException('No authorization header')

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            raise AuthException('Empty authorization header')

        return self.authenticate(raw_token, audience)

    @staticmethod
    def authenticate(raw_token: str, audience: str) -> dict:
        """
        Validation of token, if token is invalid - exception would be raised

        :param raw_token: Token from header
        :param audience: auth0 api audience
        :return: payload of token
        """
        try:
            unverified_header = jwt.get_unverified_header(raw_token)
        except jose.exceptions.JWTError:
            raise AuthException('Error decoding token headers')

        try:
            rsa_key = jwks.get_rsa_key(unverified_header["kid"])
            if not rsa_key:
                raise AuthException('JWK not found')
            payload = jwt.decode(
                raw_token,
                rsa_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=f'https://{config.auth0_domain}/')
        except jwt.ExpiredSignatureError:
            raise AuthException('Token is expired')
        except jwt.JWTClaimsError as e:
            raise AuthException('Incorrect claims, please check the audience and issuer')
        except Exception:
            raise AuthException('Unable to parse authentication header')

        return payload

    @staticmethod
    def get_header(metadata) -> Union[str, None]:
        for u in metadata:
            if u.key.lower() == 'authorization':
                return u.value
        return None

    @staticmethod
    def get_raw_token(header: str) -> str:
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.

        :param header: raw Authorization header
        :return: raw token
        """
        parts = header.split()

        if len(parts) == 0:
            raise AuthException('Empty authorization header')

        if len(parts) != 2:
            raise AuthException('Authorization header must contain two space-delimited values')

        return parts[1]
