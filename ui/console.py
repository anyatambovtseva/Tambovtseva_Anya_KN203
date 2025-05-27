import argparse
from typing import AsyncIterator, NamedTuple, Optional

from app import api


async def print_info(
    user_id: str, command_name: str, infos: Optional[AsyncIterator[NamedTuple]]
) -> None:
    print(f"Command {command_name} result for user_id={user_id}:")

    if infos is None:
        print("Incorrect user_id.")
    else:
        async for info in infos:
            fields = info._fields

            for idx, value in enumerate(info):
                print(f" * {fields[idx]}: {value}")
            print("===============================")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("user_id", help="VK user id.")
    parser.add_argument(
        "-f",
        "--friends",
        action="store_true",
        help="Print friends by user_id and specify count.",
    )
    parser.add_argument(
        "-a",
        "--albums",
        action="store_true",
        help="Print albums by user_id and specify count.",
    )
    parser.add_argument(
        "-u",
        "--userinfo",
        action="store_true",
        help="Print user info by user_id.",
    )
    parser.add_argument("-c", "--count", default=-1, type=int, help="Max records.")

    return parser


async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    user_id = args.user_id

    if args.userinfo:
        await print_info(user_id, "--userinfo", api.get_user_info(user_id))

    if args.count != -1:
        if args.count < 1:
            print("Count should be more than 1.")
    else:
        args.count = None

    if args.friends:
        await print_info(
            user_id, "--friends", api.get_user_friends(user_id, args.count)
        )
    if args.albums:
        await print_info(user_id, "--albums", api.get_user_albums(user_id, args.count))