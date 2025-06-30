import enum
import hashlib
import random
import re
import string


class ValidatedEnum(enum.Enum):
    def __new__(cls, value, regex, priority: int, *args, **kwargs):
        if not isinstance(value, str):  # Example validation: value must be an integer
            raise ValueError(f"Value '{value}' is not a string.")
        obj = object.__new__(cls)
        obj._value_ = value
        obj.regex = regex
        obj.priority = priority  # Lower number = higher priority
        return obj

    def validate(self, test_value: str) -> bool:
        return re.fullmatch(self.regex, test_value) is not None


class ObservableType(ValidatedEnum):
    IPV4 = (
        "ipaddress",
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$",
        1,
    )
    URL = (
        "url",
        "https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)",
        3,
    )
    DOMAIN = (
        "domain",
        "[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)",
        5,
    )
    MD5 = "md5", r"([a-fA-F\d]{32})", 1
    SHA1 = "sha1", r"\b[0-9a-f]{40}\b", 1
    SHA256 = "sha256", r"\b[0-9a-f]{64}\b", 1
    EMAIL = "email", r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", 1

    @classmethod
    def from_observable_value(cls, value: str):
        # Sort by priority (lower = higher priority)
        sorted_members = sorted(cls, key=lambda x: x.priority)
        for member in sorted_members:
            if member.validate(value):
                return member
        raise ValueError(f"No matching observable type for value '{value}'.")

    def get_sample_value(self) -> str:
        _domain: str = (
            "".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(7)
            )
            + "."
            + random.choice(["com", "net", "io", "org"])
        )
        if self.value == ObservableType.IPV4.value:
            return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        elif self.value == ObservableType.DOMAIN.value:
            return _domain
        elif self.value == ObservableType.URL.value:
            return f"{random.choice(['http','https','ftp','sftp'])}://{_domain}"
        elif self.value == ObservableType.EMAIL.value:
            return f"{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))}@{_domain}"
        elif self.value == ObservableType.SHA256.value:
            return random.choice([hashlib.sha256(str(''.join(random.choice(string.ascii_uppercase) for i in range(256))).encode('utf-8')).hexdigest()])
