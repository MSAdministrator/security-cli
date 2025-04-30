from typing import Dict, List

from security_cli.enrich import Enrich
from security_cli.observable import ObservableType


class Action:
    """Action class is a supporting class to support different 
    action types.
    """

    def enrich(self, value: str) -> List[Dict[str, str]]:
        ioc_type = ObservableType.from_observable_value(value)
        _enrich = Enrich()
        if ioc_type == ObservableType.IPV4:
            return _enrich.ipaddress(value)
        elif ioc_type == ObservableType.DOMAIN:
            return _enrich.domain(value)
        elif ioc_type == ObservableType.URL:
            return _enrich.url(value)
        elif ioc_type == ObservableType.EMAIL:
            return _enrich.email(value)
        return ""

    def get(self) -> None:
        raise NotImplementedError("we currently do not support getting resources")

    def block(self) -> None:
        raise NotImplementedError("we currently do not support blocking resources")

    def scan(self) -> None:
        raise NotImplementedError("we currently do not support scanning resources")

    def query(self) -> None:
        raise NotImplementedError("we currently do not support querying resources")

    def list(self) -> None:
        raise NotImplementedError("we currently do not support listing resources")
