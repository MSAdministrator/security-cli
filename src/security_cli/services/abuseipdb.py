import requests

from string import Template
from urllib.parse import urljoin

import jinja2

from security_cli.observable import ObservableType
from security_cli.services.base import BaseService


class AbuseIPDB(BaseService):
    name: str = "abuseripdb"
    host: str = "https://api.abuseipdb.com/api/v2/"
    apikey: str = "Key"


class AbuseIPDBIP(AbuseIPDB):
    endpoint: Template = Template("check")
    observable_type: ObservableType = ObservableType.IPV4

    def get(self, ipaddress: str) -> requests.PreparedRequest:
        return requests.Request(
            method=self.method,
            url=urljoin(self.host, self.endpoint.substitute()),
            params={"ipAddress": ipaddress},
            headers=self.headers,
        ).prepare()

    def parse_response(
        self, response: requests.Response, template: jinja2.Template
    ) -> str:
        if response and response.ok and response.json():
            return template.render(name=self.name, **response.json().get("data", {}))
        else:
            return ""
