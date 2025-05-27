from collections import namedtuple

DEFAULT_FIELD = "-"

sex_mapper = {DEFAULT_FIELD: "Undefined", 1: "Women", 2: "Men"}

UserInfo = namedtuple("UserInfo", ["first_name", "last_name", "sex", "bdate", "city"])

FriendInfo = namedtuple("FriendInfo", ["first_name", "last_name", "sex"])

AlbumInfo = namedtuple("AlbumInfo", ["id", "title", "size", "description"])