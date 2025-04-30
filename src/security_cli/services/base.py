from typing import Any, Dict

from security_cli.base import Base


class BaseService(Base):
    """All supported enrichment services derive from this base model.

    Args:
        host (str): The host or default URL.
        method (str, optional): The HTTP method to use. Defaults to get.
        body: (dict, optional): A body dict. Defaults to dict.
        endpoint: (str, optional): The endpoint of the url. Defaults to str.
        headers: (Dict[str, str], optional): Headers for the request. Defaults are {'accept': 'application/json'}.
    """

    host: str = ""
    method: str = "get"
    body: Dict[str, Any] = {}
    endpoint: str = ""
    headers: Dict[str, str] = {
        "accept": "application/json",
    }
