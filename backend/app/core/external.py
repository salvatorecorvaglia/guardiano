"""Validated JSON shapes at HTTP boundaries; domain objects never receive arbitrary Python values."""

from typing import Annotated, NotRequired

from pydantic import JsonValue, StrictBool, StringConstraints, TypeAdapter
from typing_extensions import TypedDict

type JsonObject = dict[str, JsonValue]
NonEmptyText = Annotated[str, StringConstraints(strict=True, min_length=1)]


class DiscoveryDocument(TypedDict, total=False):
    issuer: NonEmptyText
    authorization_endpoint: NonEmptyText
    token_endpoint: NonEmptyText
    jwks_uri: NonEmptyText


class TokenResponse(TypedDict):
    id_token: NonEmptyText


class IdentityClaims(TypedDict):
    iss: NonEmptyText
    sub: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=255)]
    email: NotRequired[Annotated[str, StringConstraints(strict=True, max_length=320)] | None]
    email_verified: NotRequired[StrictBool | None]
    name: NotRequired[Annotated[str, StringConstraints(strict=True)] | None]
    preferred_username: NotRequired[Annotated[str, StringConstraints(strict=True)] | None]


class JwkSet(TypedDict):
    keys: list[JsonObject]


JSON_DOCUMENT = TypeAdapter(JsonValue)
JSON_OBJECT = TypeAdapter(JsonObject)
DISCOVERY_DOCUMENT = TypeAdapter(DiscoveryDocument)
TOKEN_RESPONSE = TypeAdapter(TokenResponse)
JWK_SET = TypeAdapter(JwkSet)
IDENTITY_CLAIMS = TypeAdapter(IdentityClaims)
