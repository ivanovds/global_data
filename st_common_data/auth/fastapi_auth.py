import importlib
import json
import os
import pickle
from dataclasses import dataclass
import datetime
from typing import Optional, Union
from urllib.request import urlopen

import jose.exceptions
import requests
from fastapi import Request, Depends
from jose import jwt
from fastapi_exceptions.exceptions import AuthenticationFailed, PermissionDenied
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.settings import config

UserModel = getattr(
    importlib.import_module('app.models'), config.auth_user_model
)  # in tier_system AUTH_USER_MODEL="UserDataModel"
from . import SingletonMeta, SERVICE_TOKEN_FILENAME, MANAGEMENT_TOKEN_FILENAME


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


jwks = JWKS(auth0_domain=config.auth0_domain)


@dataclass(frozen=True)
class User:
    admin: bool
    user_data: UserModel
    claims: dict


def is_tier_admin(claims: dict) -> bool:
    if 'permissions' in claims and config.auth0_admin_permission in claims['permissions']:
        return True
    else:
        return False


class Auth0Authentication:
    async def authenticate_request(
        self, request: Request,
        audience: str = config.auth0_oa_api_audience
    ) -> dict:
        header = self.get_header(request)
        if header is None:
            raise AuthenticationFailed(
                detail='No authorization header')

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            raise AuthenticationFailed(
                detail='Empty authorization header')

        return await self.authenticate(raw_token, audience)

    async def authenticate(self, raw_token, audience) -> dict:
        # Validation of token, if token is invalid - exception would be raised
        try:
            unverified_header = jwt.get_unverified_header(raw_token)
        except jose.exceptions.JWTError:
            raise AuthenticationFailed(
                detail='Error decoding token headers')

        try:
            rsa_key = jwks.get_rsa_key(unverified_header["kid"])
            payload = jwt.decode(
                raw_token,
                rsa_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=f'https://{config.auth0_domain}/')
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed(
                detail='Token is expired')
        except jwt.JWTClaimsError as e:
            raise AuthenticationFailed(
                detail='Incorrect claims, please check the audience and issuer')
        except Exception:
            raise AuthenticationFailed(
                detail='Unable to parse authentication header')

        return payload

    def get_header(self, request):
        header = request.headers.get('authorization', None)
        return header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            raise AuthenticationFailed(
                detail='Empty authorization header')

        if len(parts) != 2:
            raise AuthenticationFailed(
                detail='Authorization header must contain two space-delimited values')

        return parts[1]


auth_backend = Auth0Authentication()


async def get_current_user_tp(
    request: Request,
    session: Session = Depends(get_db),
) -> User:
    claims = await auth_backend.authenticate_request(request, audience=config.auth0_tp_api_audience)
    return await get_user_from_claims(claims, session)


async def get_current_user(
    request: Request,
    session: Session = Depends(get_db),
) -> User:
    claims = await auth_backend.authenticate_request(request)
    return await get_user_from_claims(claims, session)


async def get_current_service(
    claims: dict = Depends(auth_backend.authenticate_request)
):
    if 'azp' in claims and claims['azp'] == config.auth0_service_client_id:
        return claims
    else:
        raise PermissionDenied


async def get_user_from_claims(
    claims: dict,
    session: Session,
) -> User:
    try:
        sub = claims['sub']
        sub_list = sub.split('|')
        auth_provider = sub_list[0]
        auth0_user_id = sub_list[1]
        if auth_provider != 'auth0':
            raise AuthenticationFailed(detail='Not auth0 user')
    except KeyError:
        raise AuthenticationFailed(detail='No sub in token')
    except Exception:
        raise AuthenticationFailed(detail='Invalid sub in token')

    try:
        user_data = session.query(UserModel).filter(UserModel.auth0 == auth0_user_id).one()
    except NoResultFound:
        raise PermissionDenied
    return User(
        admin=is_tier_admin(claims),
        user_data=user_data,
        claims=claims)


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
                audience=config.auth0_oa_api_audience,
                grant_type='client_credentials',
                client_id=config.auth0_service_client_id,
                client_secret=config.auth0_service_client_secret,
                services_token_url=config.auth0_service_token_url)
        elif token_filename == MANAGEMENT_TOKEN_FILENAME:
            obj_to_set = ManagementAuth0Token(
                audience=config.auth0_management_api_audience,
                grant_type='client_credentials',
                client_id=config.auth0_management_client_id,
                client_secret=config.auth0_management_client_secret,
                services_token_url=config.auth0_management_token_url)

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
