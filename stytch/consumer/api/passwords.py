# !!!
# WARNING: This file is autogenerated
# Only modify code within MANUAL() sections
# or your changes may be overwritten later!
# !!!

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from stytch.consumer.api.passwords_email import Email
from stytch.consumer.api.passwords_existing_password import ExistingPassword
from stytch.consumer.api.passwords_session import Sessions
from stytch.consumer.models.passwords import (
    Argon2Config,
    AuthenticateResponse,
    CreateResponse,
    MD5Config,
    MigrateRequestHashType,
    MigrateResponse,
    PBKDF2Config,
    ScryptConfig,
    SHA1Config,
    StrengthCheckResponse,
)
from stytch.consumer.models.users import Name
from stytch.core.api_base import ApiBase
from stytch.core.http.client import AsyncClient, SyncClient


class Passwords:
    def __init__(
        self, api_base: ApiBase, sync_client: SyncClient, async_client: AsyncClient
    ) -> None:
        self.api_base = api_base
        self.sync_client = sync_client
        self.async_client = async_client
        self.email = Email(
            api_base=self.api_base,
            sync_client=self.sync_client,
            async_client=self.async_client,
        )
        self.existing_password = ExistingPassword(
            api_base=self.api_base,
            sync_client=self.sync_client,
            async_client=self.async_client,
        )
        self.sessions = Sessions(
            api_base=self.api_base,
            sync_client=self.sync_client,
            async_client=self.async_client,
        )

    def create(
        self,
        email: str,
        password: str,
        session_duration_minutes: Optional[int] = None,
        session_custom_claims: Optional[Dict[str, Any]] = None,
        trusted_metadata: Optional[Dict[str, Any]] = None,
        untrusted_metadata: Optional[Dict[str, Any]] = None,
        name: Optional[Union[Name, Dict[str, Any]]] = None,
    ) -> CreateResponse:
        """Create a new user with a password. If `session_duration_minutes` is specified, a new session will be started as well.

        If a user with this email already exists in your Stytch project, this endpoint will return a `duplicate_email` error. To add a password to an existing passwordless user, you'll need to either call the [Migrate password endpoint](https://stytch.com/docs/api/password-migrate) or prompt the user to complete one of our password reset flows.

        This endpoint will return an error if the password provided does not meet our strength requirements, which you can check beforehand via the [Password strength check endpoint](https://stytch.com/docs/api/password-strength-check).

        When creating new Passwords users, it's good practice to enforce an email verification flow. We'd recommend checking out our [Email verification guide](https://stytch.com/docs/guides/passwords/email-verification/overview) for more information.

        Fields:
          - email: The email address of the end user.
          - password: The password for the user. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - session_duration_minutes: Set the session lifetime to be this many minutes from now. This will start a new session if one doesn't already exist,
          returning both an opaque `session_token` and `session_jwt` for this session. Remember that the `session_jwt` will have a fixed lifetime of
          five minutes regardless of the underlying session duration, and will need to be refreshed over time.

          This value must be a minimum of 5 and a maximum of 527040 minutes (366 days).

          If a `session_token` or `session_jwt` is provided then a successful authentication will continue to extend the session this many minutes.

          If the `session_duration_minutes` parameter is not specified, a Stytch session will not be created.
          - session_custom_claims: Add a custom claims map to the Session being authenticated. Claims are only created if a Session is initialized by providing a value in `session_duration_minutes`. Claims will be included on the Session object and in the JWT. To update a key in an existing Session, supply a new value. To delete a key, supply a null value.

          Custom claims made with reserved claims ("iss", "sub", "aud", "exp", "nbf", "iat", "jti") will be ignored. Total custom claims size cannot exceed four kilobytes.
          - trusted_metadata: The `trusted_metadata` field contains an arbitrary JSON object of application-specific data. See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - untrusted_metadata: The `untrusted_metadata` field contains an arbitrary JSON object of application-specific data. Untrusted metadata can be edited by end users directly via the SDK, and **cannot be used to store critical information.** See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - name: The name of the user. Each field in the name object is optional.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "email": email,
            "password": password,
        }
        if session_duration_minutes is not None:
            data["session_duration_minutes"] = session_duration_minutes
        if session_custom_claims is not None:
            data["session_custom_claims"] = session_custom_claims
        if trusted_metadata is not None:
            data["trusted_metadata"] = trusted_metadata
        if untrusted_metadata is not None:
            data["untrusted_metadata"] = untrusted_metadata
        if name is not None:
            data["name"] = name if isinstance(name, dict) else name.dict()

        url = self.api_base.url_for("/v1/passwords", data)
        res = self.sync_client.post(url, data, headers)
        return CreateResponse.from_json(res.response.status_code, res.json)

    async def create_async(
        self,
        email: str,
        password: str,
        session_duration_minutes: Optional[int] = None,
        session_custom_claims: Optional[Dict[str, Any]] = None,
        trusted_metadata: Optional[Dict[str, Any]] = None,
        untrusted_metadata: Optional[Dict[str, Any]] = None,
        name: Optional[Name] = None,
    ) -> CreateResponse:
        """Create a new user with a password. If `session_duration_minutes` is specified, a new session will be started as well.

        If a user with this email already exists in your Stytch project, this endpoint will return a `duplicate_email` error. To add a password to an existing passwordless user, you'll need to either call the [Migrate password endpoint](https://stytch.com/docs/api/password-migrate) or prompt the user to complete one of our password reset flows.

        This endpoint will return an error if the password provided does not meet our strength requirements, which you can check beforehand via the [Password strength check endpoint](https://stytch.com/docs/api/password-strength-check).

        When creating new Passwords users, it's good practice to enforce an email verification flow. We'd recommend checking out our [Email verification guide](https://stytch.com/docs/guides/passwords/email-verification/overview) for more information.

        Fields:
          - email: The email address of the end user.
          - password: The password for the user. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - session_duration_minutes: Set the session lifetime to be this many minutes from now. This will start a new session if one doesn't already exist,
          returning both an opaque `session_token` and `session_jwt` for this session. Remember that the `session_jwt` will have a fixed lifetime of
          five minutes regardless of the underlying session duration, and will need to be refreshed over time.

          This value must be a minimum of 5 and a maximum of 527040 minutes (366 days).

          If a `session_token` or `session_jwt` is provided then a successful authentication will continue to extend the session this many minutes.

          If the `session_duration_minutes` parameter is not specified, a Stytch session will not be created.
          - session_custom_claims: Add a custom claims map to the Session being authenticated. Claims are only created if a Session is initialized by providing a value in `session_duration_minutes`. Claims will be included on the Session object and in the JWT. To update a key in an existing Session, supply a new value. To delete a key, supply a null value.

          Custom claims made with reserved claims ("iss", "sub", "aud", "exp", "nbf", "iat", "jti") will be ignored. Total custom claims size cannot exceed four kilobytes.
          - trusted_metadata: The `trusted_metadata` field contains an arbitrary JSON object of application-specific data. See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - untrusted_metadata: The `untrusted_metadata` field contains an arbitrary JSON object of application-specific data. Untrusted metadata can be edited by end users directly via the SDK, and **cannot be used to store critical information.** See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - name: The name of the user. Each field in the name object is optional.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "email": email,
            "password": password,
        }
        if session_duration_minutes is not None:
            data["session_duration_minutes"] = session_duration_minutes
        if session_custom_claims is not None:
            data["session_custom_claims"] = session_custom_claims
        if trusted_metadata is not None:
            data["trusted_metadata"] = trusted_metadata
        if untrusted_metadata is not None:
            data["untrusted_metadata"] = untrusted_metadata
        if name is not None:
            data["name"] = name if isinstance(name, dict) else name.dict()

        url = self.api_base.url_for("/v1/passwords", data)
        res = await self.async_client.post(url, data, headers)
        return CreateResponse.from_json(res.response.status, res.json)

    def authenticate(
        self,
        email: str,
        password: str,
        session_token: Optional[str] = None,
        session_duration_minutes: Optional[int] = None,
        session_jwt: Optional[str] = None,
        session_custom_claims: Optional[Dict[str, Any]] = None,
    ) -> AuthenticateResponse:
        """Authenticate a user with their email address and password. This endpoint verifies that the user has a password currently set, and that the entered password is correct. There are two instances where the endpoint will return a `reset_password` error even if they enter their previous password:

        **One:** The user’s credentials appeared in the HaveIBeenPwned dataset. We force a password reset to ensure that the user is the legitimate owner of the email address, and not a malicious actor abusing the compromised credentials.

        **Two:** A user that has previously authenticated with email/password uses a passwordless authentication method tied to the same email address (e.g. Magic Links, Google OAuth) for the first time. Any subsequent email/password authentication attempt will result in this error. We force a password reset in this instance in order to safely deduplicate the account by email address, without introducing the risk of a pre-hijack account takeover attack.

        Imagine a bad actor creates many accounts using passwords and the known email addresses of their victims. If a victim comes to the site and logs in for the first time with an email-based passwordless authentication method then both the victim and the bad actor have credentials to access to the same account. To prevent this, any further email/password login attempts first require a password reset which can only be accomplished by someone with access to the underlying email address.

        Fields:
          - email: The email address of the end user.
          - password: The password for the user. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - session_token: The `session_token` associated with a User's existing Session.
          - session_duration_minutes: Set the session lifetime to be this many minutes from now. This will start a new session if one doesn't already exist,
          returning both an opaque `session_token` and `session_jwt` for this session. Remember that the `session_jwt` will have a fixed lifetime of
          five minutes regardless of the underlying session duration, and will need to be refreshed over time.

          This value must be a minimum of 5 and a maximum of 527040 minutes (366 days).

          If a `session_token` or `session_jwt` is provided then a successful authentication will continue to extend the session this many minutes.

          If the `session_duration_minutes` parameter is not specified, a Stytch session will not be created.
          - session_jwt: The `session_jwt` associated with a User's existing Session.
          - session_custom_claims: Add a custom claims map to the Session being authenticated. Claims are only created if a Session is initialized by providing a value in `session_duration_minutes`. Claims will be included on the Session object and in the JWT. To update a key in an existing Session, supply a new value. To delete a key, supply a null value.

          Custom claims made with reserved claims ("iss", "sub", "aud", "exp", "nbf", "iat", "jti") will be ignored. Total custom claims size cannot exceed four kilobytes.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "email": email,
            "password": password,
        }
        if session_token is not None:
            data["session_token"] = session_token
        if session_duration_minutes is not None:
            data["session_duration_minutes"] = session_duration_minutes
        if session_jwt is not None:
            data["session_jwt"] = session_jwt
        if session_custom_claims is not None:
            data["session_custom_claims"] = session_custom_claims

        url = self.api_base.url_for("/v1/passwords/authenticate", data)
        res = self.sync_client.post(url, data, headers)
        return AuthenticateResponse.from_json(res.response.status_code, res.json)

    async def authenticate_async(
        self,
        email: str,
        password: str,
        session_token: Optional[str] = None,
        session_duration_minutes: Optional[int] = None,
        session_jwt: Optional[str] = None,
        session_custom_claims: Optional[Dict[str, Any]] = None,
    ) -> AuthenticateResponse:
        """Authenticate a user with their email address and password. This endpoint verifies that the user has a password currently set, and that the entered password is correct. There are two instances where the endpoint will return a `reset_password` error even if they enter their previous password:

        **One:** The user’s credentials appeared in the HaveIBeenPwned dataset. We force a password reset to ensure that the user is the legitimate owner of the email address, and not a malicious actor abusing the compromised credentials.

        **Two:** A user that has previously authenticated with email/password uses a passwordless authentication method tied to the same email address (e.g. Magic Links, Google OAuth) for the first time. Any subsequent email/password authentication attempt will result in this error. We force a password reset in this instance in order to safely deduplicate the account by email address, without introducing the risk of a pre-hijack account takeover attack.

        Imagine a bad actor creates many accounts using passwords and the known email addresses of their victims. If a victim comes to the site and logs in for the first time with an email-based passwordless authentication method then both the victim and the bad actor have credentials to access to the same account. To prevent this, any further email/password login attempts first require a password reset which can only be accomplished by someone with access to the underlying email address.

        Fields:
          - email: The email address of the end user.
          - password: The password for the user. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - session_token: The `session_token` associated with a User's existing Session.
          - session_duration_minutes: Set the session lifetime to be this many minutes from now. This will start a new session if one doesn't already exist,
          returning both an opaque `session_token` and `session_jwt` for this session. Remember that the `session_jwt` will have a fixed lifetime of
          five minutes regardless of the underlying session duration, and will need to be refreshed over time.

          This value must be a minimum of 5 and a maximum of 527040 minutes (366 days).

          If a `session_token` or `session_jwt` is provided then a successful authentication will continue to extend the session this many minutes.

          If the `session_duration_minutes` parameter is not specified, a Stytch session will not be created.
          - session_jwt: The `session_jwt` associated with a User's existing Session.
          - session_custom_claims: Add a custom claims map to the Session being authenticated. Claims are only created if a Session is initialized by providing a value in `session_duration_minutes`. Claims will be included on the Session object and in the JWT. To update a key in an existing Session, supply a new value. To delete a key, supply a null value.

          Custom claims made with reserved claims ("iss", "sub", "aud", "exp", "nbf", "iat", "jti") will be ignored. Total custom claims size cannot exceed four kilobytes.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "email": email,
            "password": password,
        }
        if session_token is not None:
            data["session_token"] = session_token
        if session_duration_minutes is not None:
            data["session_duration_minutes"] = session_duration_minutes
        if session_jwt is not None:
            data["session_jwt"] = session_jwt
        if session_custom_claims is not None:
            data["session_custom_claims"] = session_custom_claims

        url = self.api_base.url_for("/v1/passwords/authenticate", data)
        res = await self.async_client.post(url, data, headers)
        return AuthenticateResponse.from_json(res.response.status, res.json)

    def strength_check(
        self,
        password: str,
        email: Optional[str] = None,
    ) -> StrengthCheckResponse:
        """This API allows you to check whether or not the user’s provided password is valid, and to provide feedback to the user on how to increase the strength of their password.

        This endpoint adapts to your Project's password strength configuration. If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your passwords are considered valid if the strength score is >= 3. If you're using [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are considered valid if they meet the requirements that you've set with Stytch. You may update your password strength configuration in the [Stytch Dashboard](https://stytch.com/dashboard/password-strength-config).


        ### Password feedback

        The `feedback` object contains relevant fields for you to relay feedback to users that failed to create a strong enough password.

        If you're using zxcvbn, the `feedback` object will contain `warning` and `suggestions` for any password that does not meet the zxcvbn strength requirements. You can return these strings directly to the user to help them craft a strong password.

        If you're using LUDS, the `feedback` object will contain an object named `luds_requirements` which contain a collection of fields that the user failed or passed. You'll want to prompt the user to create a password that meets all of the requirements that they failed.

        Fields:
          - password: The password for the user. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - email: The email address of the end user.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "password": password,
        }
        if email is not None:
            data["email"] = email

        url = self.api_base.url_for("/v1/passwords/strength_check", data)
        res = self.sync_client.post(url, data, headers)
        return StrengthCheckResponse.from_json(res.response.status_code, res.json)

    async def strength_check_async(
        self,
        password: str,
        email: Optional[str] = None,
    ) -> StrengthCheckResponse:
        """This API allows you to check whether or not the user’s provided password is valid, and to provide feedback to the user on how to increase the strength of their password.

        This endpoint adapts to your Project's password strength configuration. If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your passwords are considered valid if the strength score is >= 3. If you're using [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are considered valid if they meet the requirements that you've set with Stytch. You may update your password strength configuration in the [Stytch Dashboard](https://stytch.com/dashboard/password-strength-config).


        ### Password feedback

        The `feedback` object contains relevant fields for you to relay feedback to users that failed to create a strong enough password.

        If you're using zxcvbn, the `feedback` object will contain `warning` and `suggestions` for any password that does not meet the zxcvbn strength requirements. You can return these strings directly to the user to help them craft a strong password.

        If you're using LUDS, the `feedback` object will contain an object named `luds_requirements` which contain a collection of fields that the user failed or passed. You'll want to prompt the user to create a password that meets all of the requirements that they failed.

        Fields:
          - password: The password for the user. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - email: The email address of the end user.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "password": password,
        }
        if email is not None:
            data["email"] = email

        url = self.api_base.url_for("/v1/passwords/strength_check", data)
        res = await self.async_client.post(url, data, headers)
        return StrengthCheckResponse.from_json(res.response.status, res.json)

    def migrate(
        self,
        email: str,
        hash: str,
        hash_type: Union[MigrateRequestHashType, str],
        md_5_config: Optional[Union[MD5Config, Dict[str, Any]]] = None,
        argon_2_config: Optional[Union[Argon2Config, Dict[str, Any]]] = None,
        sha_1_config: Optional[Union[SHA1Config, Dict[str, Any]]] = None,
        scrypt_config: Optional[Union[ScryptConfig, Dict[str, Any]]] = None,
        pbkdf_2_config: Optional[Union[PBKDF2Config, Dict[str, Any]]] = None,
        trusted_metadata: Optional[Dict[str, Any]] = None,
        untrusted_metadata: Optional[Dict[str, Any]] = None,
        set_email_verified: Optional[bool] = None,
        name: Optional[Union[Name, Dict[str, Any]]] = None,
        phone_number: Optional[str] = None,
        set_phone_number_verified: Optional[bool] = None,
        external_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
    ) -> MigrateResponse:
        """Adds an existing password to a User's email that doesn't have a password yet. We support migrating users from passwords stored with `bcrypt`, `scrypt`, `argon2`, `MD-5`, `SHA-1`, or `PBKDF2`. This endpoint has a rate limit of 100 requests per second.

        Fields:
          - email: The email address of the end user.
          - hash: The password hash. For a Scrypt or PBKDF2 hash, the hash needs to be a base64 encoded string.
          - hash_type: The password hash used. Currently `bcrypt`, `scrypt`, `argon_2i`, `argon_2id`, `md_5`, `sha_1`, and `pbkdf_2` are supported.
          - md_5_config: Optional parameters for MD-5 hash types.
          - argon_2_config: Required parameters if the argon2 hex form, as opposed to the encoded form, is supplied.
          - sha_1_config: Optional parameters for SHA-1 hash types.
          - scrypt_config: Required parameters if the scrypt is not provided in a [PHC encoded form](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#phc-string-format).
          - pbkdf_2_config: Required additional parameters for PBKDF2 hash keys.
          - trusted_metadata: The `trusted_metadata` field contains an arbitrary JSON object of application-specific data. See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - untrusted_metadata: The `untrusted_metadata` field contains an arbitrary JSON object of application-specific data. Untrusted metadata can be edited by end users directly via the SDK, and **cannot be used to store critical information.** See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - set_email_verified: Whether to set the user's email as verified. This is a dangerous field, incorrect use may lead to users getting erroneously
                        deduplicated into one User object. This flag should only be set if you can attest that the user owns the email address in question.

          - name: The name of the user. Each field in the name object is optional.
          - phone_number: The phone number of the user. The phone number should be in E.164 format (i.e. +1XXXXXXXXXX).
          - set_phone_number_verified: Whether to set the user's phone number as verified. This is a dangerous field, this flag should only be set if you can attest that
           the user owns the phone number in question.
          - external_id: If a new user is created, this will set an identifier that can be used in API calls wherever a user_id is expected. This is a string consisting of alphanumeric, `.`, `_`, `-`, or `|` characters with a maximum length of 128 characters.
          - roles: (no documentation yet)
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "email": email,
            "hash": hash,
            "hash_type": hash_type,
        }
        if md_5_config is not None:
            data["md_5_config"] = (
                md_5_config if isinstance(md_5_config, dict) else md_5_config.dict()
            )
        if argon_2_config is not None:
            data["argon_2_config"] = (
                argon_2_config
                if isinstance(argon_2_config, dict)
                else argon_2_config.dict()
            )
        if sha_1_config is not None:
            data["sha_1_config"] = (
                sha_1_config if isinstance(sha_1_config, dict) else sha_1_config.dict()
            )
        if scrypt_config is not None:
            data["scrypt_config"] = (
                scrypt_config
                if isinstance(scrypt_config, dict)
                else scrypt_config.dict()
            )
        if pbkdf_2_config is not None:
            data["pbkdf_2_config"] = (
                pbkdf_2_config
                if isinstance(pbkdf_2_config, dict)
                else pbkdf_2_config.dict()
            )
        if trusted_metadata is not None:
            data["trusted_metadata"] = trusted_metadata
        if untrusted_metadata is not None:
            data["untrusted_metadata"] = untrusted_metadata
        if set_email_verified is not None:
            data["set_email_verified"] = set_email_verified
        if name is not None:
            data["name"] = name if isinstance(name, dict) else name.dict()
        if phone_number is not None:
            data["phone_number"] = phone_number
        if set_phone_number_verified is not None:
            data["set_phone_number_verified"] = set_phone_number_verified
        if external_id is not None:
            data["external_id"] = external_id
        if roles is not None:
            data["roles"] = roles

        url = self.api_base.url_for("/v1/passwords/migrate", data)
        res = self.sync_client.post(url, data, headers)
        return MigrateResponse.from_json(res.response.status_code, res.json)

    async def migrate_async(
        self,
        email: str,
        hash: str,
        hash_type: MigrateRequestHashType,
        md_5_config: Optional[MD5Config] = None,
        argon_2_config: Optional[Argon2Config] = None,
        sha_1_config: Optional[SHA1Config] = None,
        scrypt_config: Optional[ScryptConfig] = None,
        pbkdf_2_config: Optional[PBKDF2Config] = None,
        trusted_metadata: Optional[Dict[str, Any]] = None,
        untrusted_metadata: Optional[Dict[str, Any]] = None,
        set_email_verified: Optional[bool] = None,
        name: Optional[Name] = None,
        phone_number: Optional[str] = None,
        set_phone_number_verified: Optional[bool] = None,
        external_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
    ) -> MigrateResponse:
        """Adds an existing password to a User's email that doesn't have a password yet. We support migrating users from passwords stored with `bcrypt`, `scrypt`, `argon2`, `MD-5`, `SHA-1`, or `PBKDF2`. This endpoint has a rate limit of 100 requests per second.

        Fields:
          - email: The email address of the end user.
          - hash: The password hash. For a Scrypt or PBKDF2 hash, the hash needs to be a base64 encoded string.
          - hash_type: The password hash used. Currently `bcrypt`, `scrypt`, `argon_2i`, `argon_2id`, `md_5`, `sha_1`, and `pbkdf_2` are supported.
          - md_5_config: Optional parameters for MD-5 hash types.
          - argon_2_config: Required parameters if the argon2 hex form, as opposed to the encoded form, is supplied.
          - sha_1_config: Optional parameters for SHA-1 hash types.
          - scrypt_config: Required parameters if the scrypt is not provided in a [PHC encoded form](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#phc-string-format).
          - pbkdf_2_config: Required additional parameters for PBKDF2 hash keys.
          - trusted_metadata: The `trusted_metadata` field contains an arbitrary JSON object of application-specific data. See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - untrusted_metadata: The `untrusted_metadata` field contains an arbitrary JSON object of application-specific data. Untrusted metadata can be edited by end users directly via the SDK, and **cannot be used to store critical information.** See the [Metadata](https://stytch.com/docs/api/metadata) reference for complete field behavior details.
          - set_email_verified: Whether to set the user's email as verified. This is a dangerous field, incorrect use may lead to users getting erroneously
                        deduplicated into one User object. This flag should only be set if you can attest that the user owns the email address in question.

          - name: The name of the user. Each field in the name object is optional.
          - phone_number: The phone number of the user. The phone number should be in E.164 format (i.e. +1XXXXXXXXXX).
          - set_phone_number_verified: Whether to set the user's phone number as verified. This is a dangerous field, this flag should only be set if you can attest that
           the user owns the phone number in question.
          - external_id: If a new user is created, this will set an identifier that can be used in API calls wherever a user_id is expected. This is a string consisting of alphanumeric, `.`, `_`, `-`, or `|` characters with a maximum length of 128 characters.
          - roles: (no documentation yet)
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "email": email,
            "hash": hash,
            "hash_type": hash_type,
        }
        if md_5_config is not None:
            data["md_5_config"] = (
                md_5_config if isinstance(md_5_config, dict) else md_5_config.dict()
            )
        if argon_2_config is not None:
            data["argon_2_config"] = (
                argon_2_config
                if isinstance(argon_2_config, dict)
                else argon_2_config.dict()
            )
        if sha_1_config is not None:
            data["sha_1_config"] = (
                sha_1_config if isinstance(sha_1_config, dict) else sha_1_config.dict()
            )
        if scrypt_config is not None:
            data["scrypt_config"] = (
                scrypt_config
                if isinstance(scrypt_config, dict)
                else scrypt_config.dict()
            )
        if pbkdf_2_config is not None:
            data["pbkdf_2_config"] = (
                pbkdf_2_config
                if isinstance(pbkdf_2_config, dict)
                else pbkdf_2_config.dict()
            )
        if trusted_metadata is not None:
            data["trusted_metadata"] = trusted_metadata
        if untrusted_metadata is not None:
            data["untrusted_metadata"] = untrusted_metadata
        if set_email_verified is not None:
            data["set_email_verified"] = set_email_verified
        if name is not None:
            data["name"] = name if isinstance(name, dict) else name.dict()
        if phone_number is not None:
            data["phone_number"] = phone_number
        if set_phone_number_verified is not None:
            data["set_phone_number_verified"] = set_phone_number_verified
        if external_id is not None:
            data["external_id"] = external_id
        if roles is not None:
            data["roles"] = roles

        url = self.api_base.url_for("/v1/passwords/migrate", data)
        res = await self.async_client.post(url, data, headers)
        return MigrateResponse.from_json(res.response.status, res.json)
