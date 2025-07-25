# !!!
# WARNING: This file is autogenerated
# Only modify code within MANUAL() sections
# or your changes may be overwritten later!
# !!!

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from stytch.b2b.models.passwords_email import (
    RequireResetRequestOptions,
    RequireResetResponse,
    ResetRequestLocale,
    ResetResponse,
    ResetStartRequestLocale,
    ResetStartResponse,
)
from stytch.core.api_base import ApiBase
from stytch.core.http.client import AsyncClient, SyncClient


class Email:
    def __init__(
        self, api_base: ApiBase, sync_client: SyncClient, async_client: AsyncClient
    ) -> None:
        self.api_base = api_base
        self.sync_client = sync_client
        self.async_client = async_client

    def reset_start(
        self,
        organization_id: str,
        email_address: str,
        reset_password_redirect_url: Optional[str] = None,
        reset_password_expiration_minutes: Optional[int] = None,
        code_challenge: Optional[str] = None,
        login_redirect_url: Optional[str] = None,
        locale: Optional[Union[ResetStartRequestLocale, str]] = None,
        reset_password_template_id: Optional[str] = None,
        verify_email_template_id: Optional[str] = None,
    ) -> ResetStartResponse:
        """Initiates a password reset for the email address provided. This will trigger an email to be sent to the address, containing a magic link that will allow them to set a new password and authenticate.

        This endpoint adapts to your Project's password strength configuration.
        If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your passwords are considered valid
        if the strength score is >= 3. If you're using [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are
        considered valid if they meet the requirements that you've set with Stytch.
        You may update your password strength configuration on the [Passwords Policy page](https://stytch.com/dashboard/password-strength-config) in the Stytch Dashboard.

        Fields:
          - organization_id: Globally unique UUID that identifies a specific Organization. The `organization_id` is critical to perform operations on an Organization, so be sure to preserve this value. You may also use the organization_slug here as a convenience.
          - email_address: The email address of the Member to start the email reset process for.
          - reset_password_redirect_url: The URL that the Member clicks from the reset password link. This URL should be an endpoint in the backend server that verifies the request by querying
          Stytch's authenticate endpoint and finishes the reset password flow. If this value is not passed, the default `reset_password_redirect_url` that you set in your Dashboard is used.
          If you have not set a default `reset_password_redirect_url`, an error is returned.
          - reset_password_expiration_minutes: Sets a time limit after which the email link to reset the member's password will no longer be valid. The minimum allowed expiration is 5 minutes and the maximum is 10080 minutes (7 days). By default, the expiration is 30 minutes.
          - code_challenge: A base64url encoded SHA256 hash of a one time secret used to validate that the request starts and ends on the same device.
          - login_redirect_url: The URL that the member clicks from the reset without password link. This URL should be an endpoint in the backend server
              that verifies the request by querying Stytch's authenticate endpoint and finishes the magic link flow. If this value is not passed, the
              default `login_redirect_url` that you set in your Dashboard is used. This value is only used if magic links are enabled for the member. If
              you have not set a default `login_redirect_url` and magic links are not enabled for the member, an error is returned.
          - locale: Used to determine which language to use when sending the user this delivery method. Parameter is a [IETF BCP 47 language tag](https://www.w3.org/International/articles/language-tags/), e.g. `"en"`.

        Currently supported languages are English (`"en"`), Spanish (`"es"`), French (`"fr"`) and Brazilian Portuguese (`"pt-br"`); if no value is provided, the copy defaults to English.

        Request support for additional languages [here](https://docs.google.com/forms/d/e/1FAIpQLScZSpAu_m2AmLXRT3F3kap-s_mcV6UTBitYn6CdyWP0-o7YjQ/viewform?usp=sf_link")!

          - reset_password_template_id: Use a custom template for reset password emails. By default, it will use your default email template. The template must be a template using our built-in customizations or a custom HTML email for Passwords - Reset Password.
          - verify_email_template_id: Use a custom template for verification emails sent during password reset flows. When cross-organization passwords are enabled for your Project, this template will be used the first time a user sets a password via a
          password reset flow. By default, it will use your default email template. The template must be a template using our built-in customizations or a custom HTML email for Passwords - Email Verification.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "organization_id": organization_id,
            "email_address": email_address,
        }
        if reset_password_redirect_url is not None:
            data["reset_password_redirect_url"] = reset_password_redirect_url
        if reset_password_expiration_minutes is not None:
            data["reset_password_expiration_minutes"] = (
                reset_password_expiration_minutes
            )
        if code_challenge is not None:
            data["code_challenge"] = code_challenge
        if login_redirect_url is not None:
            data["login_redirect_url"] = login_redirect_url
        if locale is not None:
            data["locale"] = locale
        if reset_password_template_id is not None:
            data["reset_password_template_id"] = reset_password_template_id
        if verify_email_template_id is not None:
            data["verify_email_template_id"] = verify_email_template_id

        url = self.api_base.url_for("/v1/b2b/passwords/email/reset/start", data)
        res = self.sync_client.post(url, data, headers)
        return ResetStartResponse.from_json(res.response.status_code, res.json)

    async def reset_start_async(
        self,
        organization_id: str,
        email_address: str,
        reset_password_redirect_url: Optional[str] = None,
        reset_password_expiration_minutes: Optional[int] = None,
        code_challenge: Optional[str] = None,
        login_redirect_url: Optional[str] = None,
        locale: Optional[ResetStartRequestLocale] = None,
        reset_password_template_id: Optional[str] = None,
        verify_email_template_id: Optional[str] = None,
    ) -> ResetStartResponse:
        """Initiates a password reset for the email address provided. This will trigger an email to be sent to the address, containing a magic link that will allow them to set a new password and authenticate.

        This endpoint adapts to your Project's password strength configuration.
        If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your passwords are considered valid
        if the strength score is >= 3. If you're using [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are
        considered valid if they meet the requirements that you've set with Stytch.
        You may update your password strength configuration on the [Passwords Policy page](https://stytch.com/dashboard/password-strength-config) in the Stytch Dashboard.

        Fields:
          - organization_id: Globally unique UUID that identifies a specific Organization. The `organization_id` is critical to perform operations on an Organization, so be sure to preserve this value. You may also use the organization_slug here as a convenience.
          - email_address: The email address of the Member to start the email reset process for.
          - reset_password_redirect_url: The URL that the Member clicks from the reset password link. This URL should be an endpoint in the backend server that verifies the request by querying
          Stytch's authenticate endpoint and finishes the reset password flow. If this value is not passed, the default `reset_password_redirect_url` that you set in your Dashboard is used.
          If you have not set a default `reset_password_redirect_url`, an error is returned.
          - reset_password_expiration_minutes: Sets a time limit after which the email link to reset the member's password will no longer be valid. The minimum allowed expiration is 5 minutes and the maximum is 10080 minutes (7 days). By default, the expiration is 30 minutes.
          - code_challenge: A base64url encoded SHA256 hash of a one time secret used to validate that the request starts and ends on the same device.
          - login_redirect_url: The URL that the member clicks from the reset without password link. This URL should be an endpoint in the backend server
              that verifies the request by querying Stytch's authenticate endpoint and finishes the magic link flow. If this value is not passed, the
              default `login_redirect_url` that you set in your Dashboard is used. This value is only used if magic links are enabled for the member. If
              you have not set a default `login_redirect_url` and magic links are not enabled for the member, an error is returned.
          - locale: Used to determine which language to use when sending the user this delivery method. Parameter is a [IETF BCP 47 language tag](https://www.w3.org/International/articles/language-tags/), e.g. `"en"`.

        Currently supported languages are English (`"en"`), Spanish (`"es"`), French (`"fr"`) and Brazilian Portuguese (`"pt-br"`); if no value is provided, the copy defaults to English.

        Request support for additional languages [here](https://docs.google.com/forms/d/e/1FAIpQLScZSpAu_m2AmLXRT3F3kap-s_mcV6UTBitYn6CdyWP0-o7YjQ/viewform?usp=sf_link")!

          - reset_password_template_id: Use a custom template for reset password emails. By default, it will use your default email template. The template must be a template using our built-in customizations or a custom HTML email for Passwords - Reset Password.
          - verify_email_template_id: Use a custom template for verification emails sent during password reset flows. When cross-organization passwords are enabled for your Project, this template will be used the first time a user sets a password via a
          password reset flow. By default, it will use your default email template. The template must be a template using our built-in customizations or a custom HTML email for Passwords - Email Verification.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "organization_id": organization_id,
            "email_address": email_address,
        }
        if reset_password_redirect_url is not None:
            data["reset_password_redirect_url"] = reset_password_redirect_url
        if reset_password_expiration_minutes is not None:
            data["reset_password_expiration_minutes"] = (
                reset_password_expiration_minutes
            )
        if code_challenge is not None:
            data["code_challenge"] = code_challenge
        if login_redirect_url is not None:
            data["login_redirect_url"] = login_redirect_url
        if locale is not None:
            data["locale"] = locale
        if reset_password_template_id is not None:
            data["reset_password_template_id"] = reset_password_template_id
        if verify_email_template_id is not None:
            data["verify_email_template_id"] = verify_email_template_id

        url = self.api_base.url_for("/v1/b2b/passwords/email/reset/start", data)
        res = await self.async_client.post(url, data, headers)
        return ResetStartResponse.from_json(res.response.status, res.json)

    def reset(
        self,
        password_reset_token: str,
        password: str,
        session_token: Optional[str] = None,
        session_duration_minutes: Optional[int] = None,
        session_jwt: Optional[str] = None,
        code_verifier: Optional[str] = None,
        session_custom_claims: Optional[Dict[str, Any]] = None,
        locale: Optional[Union[ResetRequestLocale, str]] = None,
        intermediate_session_token: Optional[str] = None,
    ) -> ResetResponse:
        """Reset the Member's password and authenticate them. This endpoint checks that the password reset token is valid, hasn’t expired, or already been used.

        The provided password needs to meet our password strength requirements, which can be checked in advance with the password strength endpoint. If the token and password are accepted, the password is securely stored for future authentication and the user is authenticated.

        If the Member is required to complete MFA to log in to the Organization, the returned value of `member_authenticated` will be `false`, and an `intermediate_session_token` will be returned.
        The `intermediate_session_token` can be passed into the [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the MFA step and acquire a full member session.
        The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.

        If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an MFA step.

        Note that a successful password reset by email will revoke all active sessions for the `member_id`.

        Fields:
          - password_reset_token: The password reset token to authenticate.
          - password: The password to authenticate, reset, or set for the first time. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - session_token: Reuse an existing session instead of creating a new one. If you provide a `session_token`, Stytch will update the session.
              If the `session_token` and `magic_links_token` belong to different Members, the `session_token` will be ignored. This endpoint will error if
              both `session_token` and `session_jwt` are provided.
          - session_duration_minutes: Set the session lifetime to be this many minutes from now. This will start a new session if one doesn't already exist,
          returning both an opaque `session_token` and `session_jwt` for this session. Remember that the `session_jwt` will have a fixed lifetime of
          five minutes regardless of the underlying session duration, and will need to be refreshed over time.

          This value must be a minimum of 5 and a maximum of 527040 minutes (366 days).

          If a `session_token` or `session_jwt` is provided then a successful authentication will continue to extend the session this many minutes.

          If the `session_duration_minutes` parameter is not specified, a Stytch session will be created with a 60 minute duration. If you don't want
          to use the Stytch session product, you can ignore the session fields in the response.
          - session_jwt: Reuse an existing session instead of creating a new one. If you provide a `session_jwt`, Stytch will update the session. If the `session_jwt`
              and `magic_links_token` belong to different Members, the `session_jwt` will be ignored. This endpoint will error if both `session_token` and `session_jwt`
              are provided.
          - code_verifier: A base64url encoded one time secret used to validate that the request starts and ends on the same device.
          - session_custom_claims: Add a custom claims map to the Session being authenticated. Claims are only created if a Session is initialized by providing a value in
          `session_duration_minutes`. Claims will be included on the Session object and in the JWT. To update a key in an existing Session, supply a new value. To
          delete a key, supply a null value. Custom claims made with reserved claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) will be ignored.
          Total custom claims size cannot exceed four kilobytes.
          - locale: If the Member needs to complete an MFA step, and the Member has a phone number, this endpoint will pre-emptively send a one-time passcode (OTP) to the Member's phone number. The locale argument will be used to determine which language to use when sending the passcode.

        Parameter is a [IETF BCP 47 language tag](https://www.w3.org/International/articles/language-tags/), e.g. `"en"`.

        Currently supported languages are English (`"en"`), Spanish (`"es"`), and Brazilian Portuguese (`"pt-br"`); if no value is provided, the copy defaults to English.

        Request support for additional languages [here](https://docs.google.com/forms/d/e/1FAIpQLScZSpAu_m2AmLXRT3F3kap-s_mcV6UTBitYn6CdyWP0-o7YjQ/viewform?usp=sf_link")!

          - intermediate_session_token: Adds this primary authentication factor to the intermediate session token. If the resulting set of factors satisfies the organization's primary authentication requirements and MFA requirements, the intermediate session token will be consumed and converted to a member session. If not, the same intermediate session token will be returned.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "password_reset_token": password_reset_token,
            "password": password,
        }
        if session_token is not None:
            data["session_token"] = session_token
        if session_duration_minutes is not None:
            data["session_duration_minutes"] = session_duration_minutes
        if session_jwt is not None:
            data["session_jwt"] = session_jwt
        if code_verifier is not None:
            data["code_verifier"] = code_verifier
        if session_custom_claims is not None:
            data["session_custom_claims"] = session_custom_claims
        if locale is not None:
            data["locale"] = locale
        if intermediate_session_token is not None:
            data["intermediate_session_token"] = intermediate_session_token

        url = self.api_base.url_for("/v1/b2b/passwords/email/reset", data)
        res = self.sync_client.post(url, data, headers)
        return ResetResponse.from_json(res.response.status_code, res.json)

    async def reset_async(
        self,
        password_reset_token: str,
        password: str,
        session_token: Optional[str] = None,
        session_duration_minutes: Optional[int] = None,
        session_jwt: Optional[str] = None,
        code_verifier: Optional[str] = None,
        session_custom_claims: Optional[Dict[str, Any]] = None,
        locale: Optional[ResetRequestLocale] = None,
        intermediate_session_token: Optional[str] = None,
    ) -> ResetResponse:
        """Reset the Member's password and authenticate them. This endpoint checks that the password reset token is valid, hasn’t expired, or already been used.

        The provided password needs to meet our password strength requirements, which can be checked in advance with the password strength endpoint. If the token and password are accepted, the password is securely stored for future authentication and the user is authenticated.

        If the Member is required to complete MFA to log in to the Organization, the returned value of `member_authenticated` will be `false`, and an `intermediate_session_token` will be returned.
        The `intermediate_session_token` can be passed into the [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the MFA step and acquire a full member session.
        The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.

        If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an MFA step.

        Note that a successful password reset by email will revoke all active sessions for the `member_id`.

        Fields:
          - password_reset_token: The password reset token to authenticate.
          - password: The password to authenticate, reset, or set for the first time. Any UTF8 character is allowed, e.g. spaces, emojis, non-English characters, etc.
          - session_token: Reuse an existing session instead of creating a new one. If you provide a `session_token`, Stytch will update the session.
              If the `session_token` and `magic_links_token` belong to different Members, the `session_token` will be ignored. This endpoint will error if
              both `session_token` and `session_jwt` are provided.
          - session_duration_minutes: Set the session lifetime to be this many minutes from now. This will start a new session if one doesn't already exist,
          returning both an opaque `session_token` and `session_jwt` for this session. Remember that the `session_jwt` will have a fixed lifetime of
          five minutes regardless of the underlying session duration, and will need to be refreshed over time.

          This value must be a minimum of 5 and a maximum of 527040 minutes (366 days).

          If a `session_token` or `session_jwt` is provided then a successful authentication will continue to extend the session this many minutes.

          If the `session_duration_minutes` parameter is not specified, a Stytch session will be created with a 60 minute duration. If you don't want
          to use the Stytch session product, you can ignore the session fields in the response.
          - session_jwt: Reuse an existing session instead of creating a new one. If you provide a `session_jwt`, Stytch will update the session. If the `session_jwt`
              and `magic_links_token` belong to different Members, the `session_jwt` will be ignored. This endpoint will error if both `session_token` and `session_jwt`
              are provided.
          - code_verifier: A base64url encoded one time secret used to validate that the request starts and ends on the same device.
          - session_custom_claims: Add a custom claims map to the Session being authenticated. Claims are only created if a Session is initialized by providing a value in
          `session_duration_minutes`. Claims will be included on the Session object and in the JWT. To update a key in an existing Session, supply a new value. To
          delete a key, supply a null value. Custom claims made with reserved claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) will be ignored.
          Total custom claims size cannot exceed four kilobytes.
          - locale: If the Member needs to complete an MFA step, and the Member has a phone number, this endpoint will pre-emptively send a one-time passcode (OTP) to the Member's phone number. The locale argument will be used to determine which language to use when sending the passcode.

        Parameter is a [IETF BCP 47 language tag](https://www.w3.org/International/articles/language-tags/), e.g. `"en"`.

        Currently supported languages are English (`"en"`), Spanish (`"es"`), and Brazilian Portuguese (`"pt-br"`); if no value is provided, the copy defaults to English.

        Request support for additional languages [here](https://docs.google.com/forms/d/e/1FAIpQLScZSpAu_m2AmLXRT3F3kap-s_mcV6UTBitYn6CdyWP0-o7YjQ/viewform?usp=sf_link")!

          - intermediate_session_token: Adds this primary authentication factor to the intermediate session token. If the resulting set of factors satisfies the organization's primary authentication requirements and MFA requirements, the intermediate session token will be consumed and converted to a member session. If not, the same intermediate session token will be returned.
        """  # noqa
        headers: Dict[str, str] = {}
        data: Dict[str, Any] = {
            "password_reset_token": password_reset_token,
            "password": password,
        }
        if session_token is not None:
            data["session_token"] = session_token
        if session_duration_minutes is not None:
            data["session_duration_minutes"] = session_duration_minutes
        if session_jwt is not None:
            data["session_jwt"] = session_jwt
        if code_verifier is not None:
            data["code_verifier"] = code_verifier
        if session_custom_claims is not None:
            data["session_custom_claims"] = session_custom_claims
        if locale is not None:
            data["locale"] = locale
        if intermediate_session_token is not None:
            data["intermediate_session_token"] = intermediate_session_token

        url = self.api_base.url_for("/v1/b2b/passwords/email/reset", data)
        res = await self.async_client.post(url, data, headers)
        return ResetResponse.from_json(res.response.status, res.json)

    def require_reset(
        self,
        email_address: str,
        organization_id: Optional[str] = None,
        member_id: Optional[str] = None,
        method_options: Optional[RequireResetRequestOptions] = None,
    ) -> RequireResetResponse:
        """Require a password be reset by the associated email address. This endpoint is only functional for cross-org password use cases.

        If there are is only one active Member using the associated email address in the Project, the password will be deleted.

        Fields:
          - email_address: The email address of the Member to start the email reset process for.
          - organization_id: Globally unique UUID that identifies a specific Organization. The `organization_id` is critical to perform operations on an Organization, so be sure to preserve this value. You may also use the organization_slug here as a convenience.
          - member_id: Globally unique UUID that identifies a specific Member. The `member_id` is critical to perform operations on a Member, so be sure to preserve this value. You may use an external_id here if one is set for the member.
        """  # noqa
        headers: Dict[str, str] = {}
        if method_options is not None:
            headers = method_options.add_headers(headers)
        data: Dict[str, Any] = {
            "email_address": email_address,
        }
        if organization_id is not None:
            data["organization_id"] = organization_id
        if member_id is not None:
            data["member_id"] = member_id

        url = self.api_base.url_for("/v1/b2b/passwords/email/require_reset", data)
        res = self.sync_client.post(url, data, headers)
        return RequireResetResponse.from_json(res.response.status_code, res.json)

    async def require_reset_async(
        self,
        email_address: str,
        organization_id: Optional[str] = None,
        member_id: Optional[str] = None,
        method_options: Optional[RequireResetRequestOptions] = None,
    ) -> RequireResetResponse:
        """Require a password be reset by the associated email address. This endpoint is only functional for cross-org password use cases.

        If there are is only one active Member using the associated email address in the Project, the password will be deleted.

        Fields:
          - email_address: The email address of the Member to start the email reset process for.
          - organization_id: Globally unique UUID that identifies a specific Organization. The `organization_id` is critical to perform operations on an Organization, so be sure to preserve this value. You may also use the organization_slug here as a convenience.
          - member_id: Globally unique UUID that identifies a specific Member. The `member_id` is critical to perform operations on a Member, so be sure to preserve this value. You may use an external_id here if one is set for the member.
        """  # noqa
        headers: Dict[str, str] = {}
        if method_options is not None:
            headers = method_options.add_headers(headers)
        data: Dict[str, Any] = {
            "email_address": email_address,
        }
        if organization_id is not None:
            data["organization_id"] = organization_id
        if member_id is not None:
            data["member_id"] = member_id

        url = self.api_base.url_for("/v1/b2b/passwords/email/require_reset", data)
        res = await self.async_client.post(url, data, headers)
        return RequireResetResponse.from_json(res.response.status, res.json)
