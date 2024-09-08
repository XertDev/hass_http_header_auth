import dataclasses
import logging
from collections import OrderedDict
from http import HTTPStatus
from typing import List, cast, Any, Dict, Optional

from multidict import MultiMapping

from ipaddress import ip_address

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aiohttp.web import Request, Response
from homeassistant import data_entry_flow
from homeassistant.auth import EVENT_USER_ADDED, GROUP_ID_ADMIN
from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.components.auth import DOMAIN as AUTH_DOMAIN
from homeassistant.components.auth import indieauth
from homeassistant.components.auth.login_flow import LoginFlowIndexView
from homeassistant.components.http.ban import log_invalid_auth
from homeassistant.components.http.data_validator import RequestDataValidator
from homeassistant.core import HomeAssistant
from homeassistant.components.person import async_create_person
from homeassistant.auth.models import Credentials, User, UserMeta
from homeassistant.auth.providers import AUTH_PROVIDERS, AuthProvider, LoginFlow

_LOGGER = logging.getLogger(__name__)

DOMAIN = "http_header_auth"
CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required("user_header"): cv.string,
                vol.Required("username_header"): cv.string,
                vol.Required("groups_header"): cv.string,

                vol.Required("users_group"): cv.string,
                vol.Required("admin_group"): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


@dataclasses.dataclass
class RemoteUser:
    name: str
    username: str
    groups: List[str]


async def async_setup(hass: HomeAssistant, config):
    # based on https://github.com/BeryJu/hass-auth-header/blob/master/custom_components/auth_header/__init__.py
    router = hass.http.app.router
    for route in router._resources:
        if route.canonical == LoginFlowIndexView.url:
            router._resources.remove(route)

    if hasattr(router, "_resource_index"):
        routes = router._resource_index.get(LoginFlowIndexView.url, [])
        for route in routes:
            if route.canonical == LoginFlowIndexView.url:
                routes.remove(route)

    hass.http.register_view(
        HttpHeaderLoginFlowIndexView(
            hass.auth.login_flow, hass.data[AUTH_DOMAIN]
        )
    )

    providers = OrderedDict()
    provider = HttpHeaderAuthProvider(
        hass,
        hass.auth._store,
        config[DOMAIN],
    )
    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers

    _LOGGER.info("Http Header Auth initialized")

    return True


class HttpHeaderLoginFlowIndexView(LoginFlowIndexView):
    def __init__(self, flow_mgr, store_result) -> None:
        super().__init__(flow_mgr, store_result)

    @RequestDataValidator(
        vol.Schema(
            {
                vol.Required("client_id"): str,
                vol.Required("handler"): vol.All(
                    [vol.Any(str, None)], vol.Length(2, 2), vol.Coerce(tuple)
                ),
                vol.Required("redirect_uri"): str,
                vol.Optional("type", default="authorize"): str,
            }
        )
    )
    @log_invalid_auth
    async def post(self, request: Request, data: dict[str, Any]) -> Response:
        client_id: str = data["client_id"]
        redirect_uri: str = data["redirect_uri"]

        if not indieauth.verify_client_id(client_id):
            return self.json_message("Invalid client id", HTTPStatus.BAD_REQUEST)

        handler: tuple[str, ...] | str
        if isinstance(data["handler"], list):
            handler = tuple(data["handler"])
        else:
            handler = data["handler"]

        try:
            result = await self._flow_mgr.async_init(
                handler,
                context={
                    "headers": request.headers,
                    "ip_address": ip_address(request.remote),
                    "credential_only": data.get("type") == "link_user",
                    "redirect_uri": redirect_uri,
                },
            )
        except data_entry_flow.UnknownHandler:
            return self.json_message("Invalid handler specified", HTTPStatus.NOT_FOUND)
        except data_entry_flow.UnknownStep:
            return self.json_message(
                "Handler does not support init", HTTPStatus.BAD_REQUEST
            )

        return await self._async_flow_result_to_response(request, client_id, result)


@AUTH_PROVIDERS.register("http_header")
class HttpHeaderAuthProvider(AuthProvider):

    DEFAULT_TITLE = "Http Header Auth"
    _user_header: str
    _username_header: str
    _groups_header: str

    _users_group: str
    _admin_group: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        config = self.config
        self._user_header = config["user_header"]
        self._username_header = config["username_header"]
        self._groups_header = config["groups_header"]

        self._users_group = config["users_group"]
        self._admin_group = config["admin_group"]

    @property
    def type(self) -> str:
        return "http_auth_header"

    @property
    def support_mfa(self) -> bool:
        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        remote_user = self._extract_user_from_headers(context)

        if not remote_user:
            return HttpHeaderLoginFlow(
                self,
                None,
            )

        return HttpHeaderLoginFlow(
            self,
            remote_user,
        )

    def _extract_user_from_headers(self, context: dict[str, Any] | None) -> Optional[RemoteUser]:
        headers = cast(MultiMapping[str], context["headers"])

        if self._user_header in headers:
            _LOGGER.debug("Found user header")
            username = headers[self._username_header]
            user = headers.get(self._user_header, username)
            groups = headers.get(self._groups_header, "").split(",")
            groups = [group.strip() for group in groups]

            return RemoteUser(user, username, groups)
        return None

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        raise NotImplementedError("User should be created while fetching credentials")

    async def _async_create_user_from_headers(self, credentials: Credentials, remote_user: RemoteUser):
        is_admin = self._admin_group in remote_user.groups
        user = await self.store.async_create_user(
            credentials=credentials,
            name=remote_user.name,
            is_active=True,
            is_owner=is_admin,
            group_ids=[GROUP_ID_ADMIN if is_admin else GROUP_ID_USER],
            system_generated=False,
            local_only=False
        )
        _LOGGER.info("Created user: %s", remote_user.username)

        await async_create_person(self.hass, user.name, user_id=user.id)
        _LOGGER.info("Created person: %s", remote_user.name)
        self.hass.bus.async_fire(EVENT_USER_ADDED, {"user_id": user.id})

        return user

    async def async_get_or_create_credentials(
            self, flow_result: Dict[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        user = cast(RemoteUser, flow_result["user"])

        for credentials in await self.async_credentials():
            if "username" in credentials.data:
                if credentials.data["username"] == user.username:
                    _LOGGER.debug("Found existing credentials for user: %s", user.username)
                    return credentials

        # Let's create user
        credentials = self.async_create_credentials({"username": user.username})
        await self._async_create_user_from_headers(credentials,user)
        credentials.is_new = False

        return credentials


class HttpHeaderLoginFlow(LoginFlow):
    _remote_user: Optional[RemoteUser]

    def __init__(self, auth_provider: HttpHeaderAuthProvider, remote_user: Optional[RemoteUser]) -> None:
        super().__init__(auth_provider)
        self._remote_user = remote_user

    async def async_step_init(self, user_input=None) -> Dict[str, Any]:
        if user_input is not None:
            if self._remote_user:
                return await self.async_finish({
                    "user": self._remote_user
                })

            _LOGGER.debug("User not provided in request")
            return self.async_abort(reason="not_allowed")

        return self.async_show_form(
            step_id="init",
            data_schema=None,
        )
