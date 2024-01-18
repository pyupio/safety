import configparser
import json

from typing import Any, Dict, Optional, Tuple, Union

from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError

from safety.auth.models import Organization
from safety.auth.constants import AUTH_SERVER_URL, CLI_AUTH_LOGOUT, CLI_CALLBACK, AUTH_CONFIG_USER, CLI_AUTH
from safety.constants import CONFIG
from safety.errors import NotVerifiedEmailError
from safety.scan.util import Stage
from safety.util import get_proxy_dict


def get_authorization_data(client, code_verifier: str,
                           organization: Optional[Organization] = None, 
                           sign_up: bool = False, ensure_auth: bool = False) -> Tuple[str, str]:
    
    kwargs = {'sign_up': sign_up, 'locale': 'en', 'ensure_auth': ensure_auth}
    if organization:
        kwargs['organization'] = organization.id

    return client.create_authorization_url(CLI_AUTH,
                                           code_verifier=code_verifier,
                                           **kwargs)

def get_logout_url(id_token: str) -> str:
    return f'{CLI_AUTH_LOGOUT}?id_token={id_token}'

def get_redirect_url() -> str:
    return CLI_CALLBACK

def get_organization() -> Optional[Organization]:
    config = configparser.ConfigParser()
    config.read(CONFIG)

    org_conf: Union[Dict[str, str], configparser.SectionProxy] = config[
        'organization'] if 'organization' in config.sections() else {}
    org_id: Optional[str] = org_conf['id'].replace("\"", "") if org_conf.get('id', None) else None
    org_name: Optional[str] = org_conf['name'].replace("\"", "") if org_conf.get('name', None) else None

    if not org_id:
        return None

    org = Organization(
        id=org_id,
        name=org_name
    )

    return org

def get_auth_info(ctx):
    info = None
    if ctx.obj.auth.client.token:
        try:
            info = get_token_data(get_token(name='id_token'), keys=ctx.obj.auth.keys)

            verified = info.get("email_verified", False)
            if not verified:
                user_info = ctx.obj.auth.client.fetch_user_info()
                verified = user_info.get("email_verified", False)

                if verified:
                    # refresh only if needed 
                    raise ExpiredTokenError

        except ExpiredTokenError as e:
            # id_token expired. So fire a manually a refresh
            try:
                ctx.obj.auth.client.refresh_token(ctx.obj.auth.client.metadata.get('token_endpoint'),
                                         refresh_token=ctx.obj.auth.client.token.get('refresh_token'))
                info = get_token_data(get_token(name='id_token'), keys=ctx.obj.auth.keys)
            except Exception as _e:
                clean_session(ctx.obj.auth.client)
        except Exception as _g:
            clean_session(ctx.obj.auth.client)
    
    return info

def get_token_data(token, keys, silent_if_expired=False) -> Optional[Dict]:
    claims = jwt.decode(token, keys, claims_cls=CodeIDToken)
    try:
        claims.validate()
    except ExpiredTokenError as e:
        if not silent_if_expired:
            raise e

    return claims

def get_token(name='access_token') -> Optional[str]:
    """"
    This returns tokens saved in the local auth configuration.
    There are two types of tokens: access_token and id_token
    """
    config = configparser.ConfigParser()
    config.read(AUTH_CONFIG_USER)

    if 'auth' in config.sections() and name in config['auth']:
        value = config['auth'][name]
        if value:
            return value

    return None

def get_host_config(key_name) -> Optional[Any]:
    config = configparser.ConfigParser()
    config.read(CONFIG)

    if not config.has_section("host"):
        return None
    
    host_section = dict(config.items("host"))

    if key_name in host_section:
        if key_name == "stage":
            # Support old alias in the config.ini
            if host_section[key_name] == "dev":
                host_section[key_name] = "development"
            if host_section[key_name] not in {env.value for env in Stage}:
                return None
            return Stage(host_section[key_name])

    return None

def str_to_bool(s):
    """Convert a string to a boolean value."""
    if s.lower() == 'true' or s == '1':
        return True
    elif s.lower() == 'false' or s == '0':
        return False
    else:
        raise ValueError(f"Cannot convert '{s}' to a boolean value.")

def get_proxy_config() -> Tuple[Dict[str, str], Optional[int], bool]:
    config = configparser.ConfigParser()
    config.read(CONFIG)

    proxy_dictionary =  None
    required = False
    timeout = None
    proxy = None

    if config.has_section("proxy"):
        proxy = dict(config.items("proxy"))

    if proxy:
        try:
            proxy_dictionary = get_proxy_dict(proxy['protocol'], proxy['host'], 
                                                proxy['port'])
            required = str_to_bool(proxy["required"])
            timeout = proxy["timeout"]
        except Exception as e:
            pass

    return proxy_dictionary, timeout, required

def clean_session(client):
    config = configparser.ConfigParser()
    config['auth'] = {'access_token': '', 'id_token': '', 'refresh_token':''}

    with open(AUTH_CONFIG_USER, 'w') as configfile:
        config.write(configfile)

    client.token = None

    return True

def save_auth_config(access_token=None, id_token=None, refresh_token=None):
    config = configparser.ConfigParser()
    config.read(AUTH_CONFIG_USER)
    config['auth'] = {'access_token': access_token, 'id_token': id_token, 
                      'refresh_token': refresh_token}
    
    with open(AUTH_CONFIG_USER, 'w') as configfile:
        config.write(configfile)
