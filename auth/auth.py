import json
import logging
import string
from typing import Any, Awaitable, Callable
import inspect
import requests
from typing import Any, Awaitable, Callable, Dict  # NOQA

from fastapi import Request, HTTPException
from jose import jwt
from jose import exceptions

from auth.settings import DEFAULT_USER, SETTINGS
# from wic.wic_types import Json

TIMEOUT = 60  # seconds

logging.basicConfig(
    format="%(asctime)s - %(name)-8s - %(levelname)-8s - %(message)s",
    datefmt="%d-%b-%y %H:%M:%S",
)
logger = logging.getLogger("wic.auth")

IS_OFFLINE = (
    SETTINGS.AUTH_BASE_URL is None
    and SETTINGS.JWKS_ENDPOINT is None
    and SETTINGS.ALGORITHMS is None
)
if IS_OFFLINE:
    logger.warning(
        "AUTH_BASE_URL, JWKS_ENDPOINT, and/or ALGORITHMS is not defined in the "
        + "the environment file. Endpoints will not be authenticated."
    )


def get_user_info(token: str) -> Dict[str, Any]:
    """Obtains the data for a user from the 'me' endpoint given a Bearer token.

    Args:
        token: Bearer token from Authorization Header
    """
    headers = {"Authorization": "Bearer " + token}
    body_data = {"json": True}
    userData = requests.post(
        f"{SETTINGS.AUTH_BASE_URL}/{SETTINGS.ME_ENDPOINT}",
        data=body_data,
        headers=headers,
    ).json()
    return userData


def get_token_auth_header(request: Request) -> str:
    """Obtains the Access Token from the Authorization Header.

    Args:
        request (Request): request object

    Returns:
        token: token
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise HTTPException(status_code=401, detail="Authorization header is expected")

    parts = auth.split()

    if parts[0].lower() != "bearer" or len(parts) > 2:
        raise HTTPException(
            status_code=401, detail="Authorization header must start with Bearer"
        )
    elif len(parts) == 1:
        raise HTTPException(status_code=401, detail="Token not found.")

    token: str = parts[1]
    return token


def get_user(request: Request) -> Dict[Any, Any]:
    """Gets user information from Request object."""
    token = get_token_auth_header(request)
    return get_user_info(token)


def normalize_text(text: str) -> str:
    """Replaces punctuation with underscare in text.

    Args:
        text (str): text string to normalize

    Returns:
        str: normalized string
    """
    return text.translate(
        str.maketrans(string.punctuation, "_" * len(string.punctuation))
    )


def authenticate(func: Callable[..., Any]) -> Callable[..., Any]:
    """Authenticate header information with jwt.
    This is a decorator for authenticated endpoints in wic. In order for
    authentication to be turned on, the .env file must have the AUTH_BASE_URL,
    JWKS_ENDPOINT, and ALGORITHM values set.

    Args:
        func (Callable): Function to wrap with authentication methods.

    Returns:
        Returns a wrapped API endpoint.
    """
    async def wrapper(*args: Any, **kwargs: Any) -> Awaitable[Any]:
        request: Request = kwargs["request"]

        if SETTINGS.OFFLINE_USER is not None:
            request.state.user_id = SETTINGS.OFFLINE_USER
        else:
            request.state.user_id = DEFAULT_USER

        if IS_OFFLINE:
            return await func(*args, **kwargs)


        token = get_token_auth_header(request)
        print(token)
        
        jwks = requests.get(
            f"{SETTINGS.AUTH_BASE_URL}/{SETTINGS.JWKS_ENDPOINT}", verify=False
        ).json()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = key
                break
        if rsa_key:
            try:
                jwt.decode(  # NOQA: F841
                    token,
                    rsa_key,
                    algorithms=[SETTINGS.ALGORITHMS],
                    audience=SETTINGS.AUTH_BASE_URL,
                    issuer=SETTINGS.AUTH_BASE_URL,
                )
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="token is expired")
            except jwt.JWTClaimsError:
                raise HTTPException(
                    status_code=401,
                    detail="incorrect claims, please check the audience and issuer",
                )
            except Exception:
                raise HTTPException(
                    status_code=401, detail="Unable to parse authentication token."
                )
            if SETTINGS.OFFLINE_USER is None:
                user_data = get_user(request)
                if "email" not in user_data:
                    raise HTTPException(status_code=401, detail="Claims not found.")
                email = user_data["email"]
                if email is not None:
                    request.state.user_id = normalize_text(email)
            return await func(*args, **kwargs)
        raise HTTPException(status_code=401, detail="Unable to find appropriate key.")

    wrapper.__signature__ = inspect.Signature(  # type: ignore
        parameters=[
            # Skip *args and **kwargs from wrapper parameters:
            *filter(
                lambda p: p.kind
                not in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                ),
                inspect.signature(wrapper).parameters.values(),
            ),
            # Use all parameters from handler
            *inspect.signature(func).parameters.values(),
        ],
        return_annotation=inspect.signature(func).return_annotation,
    )

    return wrapper

#     async def wrapper(*args: Any, **kwargs: Any) -> Awaitable[Any]:
#         print('wrapper')
#         print(kwargs)
#         request: Request = kwargs["request"]
#         print('wrapper')
#         print(request)

#         if SETTINGS.OFFLINE_USER is not None:
#             request.state.user_id = SETTINGS.OFFLINE_USER
#         else:
#             request.state.user_id = DEFAULT_USER

#         if IS_OFFLINE:
#             await func(*args, **kwargs)

#         # logging.debug(f"Calling {func.__name__} with auth.")
#         token = get_token_auth_header(request)
#         print('token')
#         print(token)

#         jwks = requests.get(
#             f"{SETTINGS.AUTH_BASE_URL}/{SETTINGS.JWKS_ENDPOINT}",
#             verify=False, timeout=TIMEOUT
#         ).json()
#         unverified_header = jwt.get_unverified_header(token)
#         rsa_key = {}
#         for key in jwks["keys"]:
#             if key["kid"] == unverified_header["kid"]:
#                 rsa_key = key
#                 break
#         if rsa_key:
#             try:
#                 jwt.decode(  # NOQA: F841
#                     token,
#                     rsa_key,
#                     algorithms=SETTINGS.ALGORITHMS,
#                     audience=SETTINGS.AUTH_BASE_URL,
#                     issuer=SETTINGS.AUTH_BASE_URL,
#                 )
#             except exceptions.ExpiredSignatureError as exc:
#                 raise HTTPException(status_code=401, detail="token is expired") from exc
#             except exceptions.JWTClaimsError as exc:
#                 raise HTTPException(
#                     status_code=401,
#                     detail="incorrect claims, please check the audience and issuer",
#                 ) from exc
#             except Exception as exc:
#                 raise HTTPException(
#                     status_code=401, detail="Unable to parse authentication token."
#                 ) from exc
                
#             # await func(*args, **kwargs)
#             if SETTINGS.OFFLINE_USER is None:
#                 user_data = get_user(request)
#                 if "email" not in user_data:
#                     raise HTTPException(status_code=401, detail="Claims not found.")
#                 email = user_data["email"]
#                 if email is not None:
#                     request.state.user_id = normalize_text(email)
#                     request.session["user_id"] = request.state.user_id
#             return await func(*args, **kwargs)
#         raise HTTPException(status_code=401, detail="Unable to find appropriate key.")

#     wrapper.__signature__ = inspect.Signature(  # type: ignore
#         parameters=[
#             # Skip *args and **kwargs from wrapper parameters:
#             *filter(
#                 lambda p: p.kind
#                 not in (
#                     inspect.Parameter.VAR_POSITIONAL,
#                     inspect.Parameter.VAR_KEYWORD,
#                 ),
#                 inspect.signature(wrapper).parameters.values(),
#             ),
#             # Use all parameters from handler
#             *inspect.signature(func).parameters.values(),
#         ],
#         return_annotation=inspect.signature(func).return_annotation,
#     )

#     return wrapper



