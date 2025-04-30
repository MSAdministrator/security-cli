import requests

from string import Template
from urllib.parse import urljoin

import jinja2

from security_cli.observable import ObservableType
from security_cli.services.base import BaseService


class HaveIBeenPwned(BaseService):
    name: str = "hibp"
    host: str = "https://haveibeenpwned.com/api/v3/"
    apikey: str = "hibp-api-key"


class HaveIBeenPwnedEmail(HaveIBeenPwned):
    endpoint: Template = Template("breachedaccount/${email}?truncateResponse=false")
    observable_type: ObservableType = ObservableType.EMAIL

    def get(self, email: str) -> requests.PreparedRequest:
        return requests.Request(
            method=self.method,
            url=urljoin(self.host, self.endpoint.substitute(email=email)),
            headers=self.headers,
        ).prepare()

    def parse_response(
        self, response: requests.Response, template: jinja2.Template
    ) -> str:
        if response and response.ok and response.json():
            return template.render(
                name=self.name,
                email=response.url.split("/")[-1].split("?")[0],
                response=response.json(),
            )
        else:
            return ""
