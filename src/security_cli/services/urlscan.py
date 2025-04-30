import requests

from string import Template
from urllib.parse import urljoin, urlparse

import jinja2

from security_cli.observable import ObservableType
from security_cli.services.base import BaseService


class Urlscan(BaseService):
    name: str = "urlscan"
    host: str = "https://urlscan.io/api/v1/"
    apikey: str = "API-Key"


class UrlscanIP(Urlscan):
    endpoint: Template = Template("search/?q=ip:$ipaddress")
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
            return template.render(
                name=self.name,
                **(
                    response.json().get("results")[0]
                    if len(response.json().get("results")) > 0
                    else {}
                ),
            )
        else:
            return ""


class UrlscanDomain(Urlscan):
    endpoint: Template = Template("search/?q=domain:$domain")
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
            return template.render(
                name=self.name,
                **(
                    response.json().get("results")[0]
                    if len(response.json().get("results")) > 0
                    else {}
                ),
            )
        else:
            return ""


class UrlscanUrl(Urlscan):
    endpoint: Template = Template("search/?q=domain:$url")
    observable_type: ObservableType = ObservableType.URL

    def get(self, url: str) -> requests.PreparedRequest:
        return requests.Request(
            method=self.method,
            url=urljoin(self.host, self.endpoint.substitute(url=urlparse(url).netloc)),
            headers=self.headers,
        ).prepare()

    def parse_response(
        self, response: requests.Response, template: jinja2.Template
    ) -> str:
        if response and response.ok and response.json():
            return template.render(
                name=self.name,
                **(
                    response.json().get("results")[0]
                    if len(response.json().get("results")) > 0
                    else {}
                ),
            )
        else:
            return ""
