import requests

from string import Template
from urllib.parse import urljoin

import jinja2

from security_cli.observable import ObservableType
from security_cli.services.base import BaseService


class Shodan(BaseService):
    name: str = "shodan"
    host: str = "https://api.shodan.io/"
    apikey: str = ""


class ShodanIP(Shodan):
    endpoint: Template = Template("shodan/host/$ipaddress?key=")
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
            return template.render(name=self.name, **response.json())
        else:
            return ""


class ShodanDomain(Shodan):
    endpoint: Template = Template("dns/domain/$domain?key=")
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
            return template.render(name=self.name, **response.json())
        else:
            return ""
