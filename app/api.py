from typing import AsyncIterator, Dict, Optional
from urllib import parse

import aiohttp

from app import dependencies
from app.data import *

settings = dependencies.get_server_settings()


async def get_user_info(user_id: str) -> Optional[AsyncIterator[UserInfo]]:
    response = await _get_response(
        "users.get", user_id, fields=",".join(UserInfo._fields)
    )

    if "response" in response and len(response["response"]) > 0:
        info = response["response"][0]

        yield UserInfo(
            first_name=info.get("first_name", DEFAULT_FIELD),
            last_name=info.get("last_name", DEFAULT_FIELD),
            bdate=info.get("bdate", DEFAULT_FIELD),
            sex=sex_mapper[info.get("sex", DEFAULT_FIELD)],
            city=info.get("city", {"title": DEFAULT_FIELD}).get("title", DEFAULT_FIELD),
        )


async def get_user_friends(
    user_id: str, count: Optional[int] = None
) -> Optional[AsyncIterator[FriendInfo]]:
    params = {"order": "hints", "fields": ",".join(FriendInfo._fields)}

    if count is not None:
        params["count"] = count

    response = await _get_response("friends.get", user_id, **params)

    if "response" in response and "items" in response["response"]:
        infos = response["response"]["items"]

        for info in infos:
            yield FriendInfo(
                first_name=info.get("first_name", DEFAULT_FIELD),
                last_name=info.get("last_name", DEFAULT_FIELD),
                sex=sex_mapper[info.get("sex", DEFAULT_FIELD)],
            )


async def get_user_albums(
    user_id: str, count: Optional[int] = None
) -> Optional[AsyncIterator[AlbumInfo]]:
    params = dict()

    if count is not None:
        params["count"] = count

    response = await _get_response("photos.getAlbums", user_id, **params)

    if "response" in response and "items" in response["response"]:
        infos = response["response"]["items"]

        for info in infos:
            yield AlbumInfo(
                id=info.get("id", DEFAULT_FIELD),
                title=info.get("title", DEFAULT_FIELD),
                description=info.get("description", DEFAULT_FIELD),
                size=info.get("size", DEFAULT_FIELD),
            )


def _get_method_url(method: str, **params) -> str:
    return f"{settings['vk_api_url']}{method}?{parse.urlencode(params)}"


async def _get_response(method: str, user_id: str, **kwargs) -> Dict:
    url = _get_method_url(
        method=method,
        user_id=user_id,
        access_token=settings["access_token"],
        v=settings["vk_api_version"],
        **kwargs,
    )

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()