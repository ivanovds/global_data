import importlib
import json
import datetime
import os
import pickle
from typing import Optional, Union
from urllib.request import urlopen

import requests
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework import HTTP_HEADER_ENCODING, authentication
from rest_framework.exceptions import AuthenticationFailed
import jose.exceptions
from jose import jwt

from . import SingletonMeta, SERVICE_TOKEN_FILENAME, MANAGEMENT_TOKEN_FILENAME

UserModel = get_user_model()


class JWKS(metaclass=SingletonMeta):
    """
    Auth0 json web keys set for local token verification
    """

    def __init__(self, auth0_domain: str):
        self.auth0_domain: str = auth0_domain
        self._jwks_keys: dict = dict()

        self._update_jwks()

    def get_rsa_key(self, kid: str) -> Optional[dict]:
        try:
            return self._jwks_keys[kid]
        except KeyError:
            self._update_jwks()
            if kid not in self._jwks_keys:
                raise AuthenticationFailed(
                    detail='Unable to find appropriate key')
            return self._jwks_keys[kid]

    def _update_jwks(self):
        jsonurl = urlopen(f"https://{self.auth0_domain}/.well-known/jwks.json")
        self._jwks_keys = dict()
        for key in json.loads(jsonurl.read())['keys']:
            self._jwks_keys[key['kid']] = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]}


jwks = JWKS(auth0_domain=settings.AUTH0_DOMAIN)


class Filter:
    def __init__(self, *args, **kwargs):
        pass

    def exists(self):
        """give all group permission for service user"""
        return True


class QS:
    filter = Filter


class ServiceUser:
    """Dummy user for auth of services that use okta Service Credential flow"""
    def __init__(self):
        self.is_authenticated = True  # for IsAuthenticated permission class
        self.groups = QS  # for all groups permissions


class Auth0Authentication(authentication.BaseAuthentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header.
    """
    www_authenticate_realm = 'api'
    auth0_api_audience = settings.AUTH0_API_AUDIENCE

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        try:
            unverified_header = jwt.get_unverified_header(raw_token)
        except jose.exceptions.JWTError:
            raise AuthenticationFailed(
                detail='Error decoding token headers')

        rsa_key = jwks.get_rsa_key(unverified_header["kid"])
        try:
            claims = jwt.decode(
                raw_token,
                rsa_key,
                algorithms=["RS256"],
                audience=self.auth0_api_audience,
                issuer=f'https://{settings.AUTH0_DOMAIN}/')
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed(
                detail='Token is expired')
        except jwt.JWTClaimsError:
            return None  # try another authentication instance
        except Exception:
            raise AuthenticationFailed(
                detail='Unable to parse authentication header')

        user = self.get_user(claims)
        if not user:
            return None
        else:
            return user, claims

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get('HTTP_AUTHORIZATION')

        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode(HTTP_HEADER_ENCODING)

        return header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                detail='Authorization header must contain two space-delimited values',
                code='bad_authorization_header',
            )

        return parts[1]

    def get_user(self, claims: dict):
        try:
            sub = claims['sub']
            sub_list = sub.split('|')
            auth_provider = sub_list[0]
            user_id = sub_list[1]
            if auth_provider != 'auth0':
                return None
        except KeyError:
            raise AuthenticationFailed(detail='No sub in token')
        except Exception:
            return None

        try:
            return UserModel.objects.get(auth0=user_id)
        except (UserModel.DoesNotExist, KeyError):
            return None


class Auth0ServiceAuthentication(Auth0Authentication):
    """
    An authentication plugin for service auth.
    """
    www_authenticate_realm = 'api'

    def get_user(self, claims):
        if 'azp' in claims and claims['azp'] == settings.AUTH0_SERVICE_CLIENT_ID:
            return ServiceUser()
        else:
            return None


class Auth0CAPServiceAuthentication(Auth0ServiceAuthentication):
    """
    An authentication plugin for service auth (for CAP api).
    """
    auth0_api_audience = settings.AUTH0_CAP_API_AUDIENCE


class Auth0CAPAuthentication(Auth0Authentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header (for CAP api).
    """
    auth0_api_audience = settings.AUTH0_CAP_API_AUDIENCE


class Auth0PineServiceAuthentication(Auth0ServiceAuthentication):
    """
    An authentication plugin for service auth (for pine_api).
    """
    auth0_api_audience = settings.AUTH0_PINE_API_AUDIENCE


class Auth0BackOfficeServiceAuthentication(Auth0ServiceAuthentication):
    """
    An authentication plugin for service auth (for bo_api).
    """
    auth0_api_audience = settings.AUTH0_BO_API_AUDIENCE


class Auth0PineAuthentication(Auth0Authentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header (for pine_api).
    """
    auth0_api_audience = settings.AUTH0_PINE_API_AUDIENCE


class ServiceAuth0Token(metaclass=SingletonMeta):
    """
    Auth0 token from service app for machine-to-machine communication (between services)
    """
    TOKEN_FILENAME = SERVICE_TOKEN_FILENAME

    def __init__(self,
                 audience: str,
                 grant_type: str,
                 client_id: str,
                 client_secret: str,
                 services_token_url: str):
        self.audience = audience
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = services_token_url
        self.expire = None
        self._token = ''

    @property
    def token(self):
        if not self.expire or self.expire < datetime.datetime.now():
            self._update_token()
        return self._token

    def _update_token(self):
        token_data = self._get_token()
        self._token = token_data['access_token']
        self.expire = datetime.datetime.now() + datetime.timedelta(seconds=token_data['expires_in'] - 10)
        create_or_update_token_file(obj_to_set=self, token_filename=self.TOKEN_FILENAME)

    def _get_token(self, retry: int = 2):
        response = requests.post(
            url=self.token_url,
            data={
                'audience': self.audience,
                'grant_type': self.grant_type,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=2)
        if response.status_code == 200:
            return response.json()
        else:
            while retry > 0:
                self._get_token(retry=retry-1)
            try:
                details = response.json()
            except:
                details = response.text
            raise Exception(f'Unable to get token, status code: {response.status_code}. Server returned: {details}')

    def __str__(self):
        return self.token


class ManagementAuth0Token(ServiceAuth0Token):
    """
    Auth0 token from management app for communication with auth0 API
    """
    TOKEN_FILENAME = MANAGEMENT_TOKEN_FILENAME


def create_or_update_token_file(token_filename: str,
                                obj_to_set: Union[ServiceAuth0Token, ManagementAuth0Token] = None) -> None:
    if obj_to_set is None:

        if token_filename == SERVICE_TOKEN_FILENAME:
            obj_to_set = ServiceAuth0Token(
                audience=settings.AUTH0_API_AUDIENCE,
                grant_type='client_credentials',
                client_id=settings.AUTH0_SERVICE_CLIENT_ID,
                client_secret=settings.AUTH0_SERVICE_CLIENT_SECRET,
                services_token_url=settings.AUTH0_SERVICE_TOKEN_URL)
        elif token_filename == MANAGEMENT_TOKEN_FILENAME:
            obj_to_set = ManagementAuth0Token(
                audience=settings.AUTH0_MANAGEMENT_API_AUDIENCE,
                grant_type='client_credentials',
                client_id=settings.AUTH0_MANAGEMENT_CLIENT_ID,
                client_secret=settings.AUTH0_MANAGEMENT_CLIENT_SECRET,
                services_token_url=settings.AUTH0_MANAGEMENT_TOKEN_URL
            )

    obj_to_set.token  # Important! In order to set token before saving into file

    with open(token_filename, 'wb') as wb_handle:
        pickle.dump(obj_to_set, wb_handle, protocol=pickle.HIGHEST_PROTOCOL)


def get_auth0_token(token_filename: str, retry: int = 0) -> Union[ServiceAuth0Token, ManagementAuth0Token]:
    if retry > 2:
        raise Exception('Failed to get_service_auth0_token after several retries')

    if not os.path.exists(token_filename):
        create_or_update_token_file(token_filename=token_filename)

    with open(token_filename, 'rb') as rb_handle:
        try:
            token = pickle.load(rb_handle)
        except:
            os.remove(token_filename)
            token = get_auth0_token(token_filename=token_filename, retry=retry + 1)
    return token


service_auth0_token = get_auth0_token(token_filename=SERVICE_TOKEN_FILENAME)
management_auth0_token = get_auth0_token(token_filename=MANAGEMENT_TOKEN_FILENAME)
