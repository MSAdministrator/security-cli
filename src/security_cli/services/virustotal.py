import requests

from string import Template
from urllib.parse import urljoin

import jinja2

from security_cli.observable import ObservableType
from security_cli.services.base import BaseService


class VirusTotal(BaseService):
    name: str = "virustotal"
    host: str = "https://www.virustotal.com/api/v3/"
    apikey: str = "x-apikey"


class VirusTotalIP(VirusTotal):
    endpoint: Template = Template("ip_addresses/$ipaddress")
    observable_type: ObservableType = ObservableType.IPV4

    def get(self, ipaddress: str) -> requests.PreparedRequest:
        return requests.Request(
            method=self.method,
            url=urljoin(self.host, self.endpoint.substitute(ipaddress=ipaddress)),
            headers=self.headers,
        ).prepare()

    def parse_response(
        self, response: requests.Response, template: jinja2.Template
    ) -> str:
        if response and response.ok and response.json():
            return template.render(name=self.name, **response.json().get("data", {}))
        else:
            return ""


class VirusTotalDomain(VirusTotal):
    endpoint: str = Template("domains/$domain")
    observable_type: ObservableType = ObservableType.DOMAIN

    def get(self, domain: str) -> requests.PreparedRequest:
        return requests.Request(
            method=self.method,
            url=urljoin(self.host, self.endpoint.substitute(domain=domain)),
            headers=self.headers,
        ).prepare()

    def parse_response(
        self, response: requests.Response, template: jinja2.Template
    ) -> str:
        if response and response.ok and response.json():
            return template.render(name=self.name, **response.json().get("data", {}))
        else:
            return ""
