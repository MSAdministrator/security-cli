from typing import Dict

import requests

from security_cli.base import Base
from security_cli.services import (
    EnrichmentService,
    VirusTotalIP,
    VirusTotalDomain,
    AlienVaultIP,
    AlienVaultDomain,
    ShodanIP,
    ShodanDomain,
    HybridAnalysisIP,
    HybridAnalysisDomain,
    UrlscanIP,
    UrlscanDomain,
    UrlscanUrl,
    AbuseIPDBIP,
    HaveIBeenPwnedEmail,
)
from security_cli.observable import ObservableType


ALL_LOOKUP_SERVICES: Dict[ObservableType, Dict[str, EnrichmentService]] = {
    ObservableType.IPV4: {
        AbuseIPDBIP.name: AbuseIPDBIP,
        AlienVaultIP.name: AlienVaultIP,
        HybridAnalysisIP.name: HybridAnalysisIP,
        ShodanIP.name: ShodanIP,
        UrlscanIP.name: UrlscanIP,
        VirusTotalIP.name: VirusTotalIP,
    },
    ObservableType.DOMAIN: {
        AlienVaultDomain.name: AlienVaultDomain,
        HybridAnalysisDomain.name: HybridAnalysisDomain,
        ShodanDomain.name: ShodanDomain,
        UrlscanDomain.name: UrlscanDomain,
        VirusTotalDomain.name: VirusTotalDomain,
    },
    ObservableType.URL: {
        UrlscanUrl.name: UrlscanUrl,
    },
    ObservableType.EMAIL: {
        HaveIBeenPwnedEmail.name: HaveIBeenPwnedEmail,
    },
}


class Enrich(Base):

    def _process_source(self, value: str, observable_type: ObservableType) -> str:
        responses: Dict[str, str] = {}
        error_string: str = (
            f"error occurred looking up value '{value}' in '{observable_type.value}'"
        )
        for source in getattr(self._config.actions.enrich, observable_type.value):
            if ALL_LOOKUP_SERVICES[observable_type].get(source.name):
                service = ALL_LOOKUP_SERVICES[observable_type][source.name]()
                req = service.get(value)

                # Edge case with shodan here
                if source.name == "shodan":
                    req.url = f"{req.url}{source.apikey}"
                else:
                    req.headers[service.apikey] = source.apikey

                # HA wants this in the body, another edge case
                if source.name == "hybridanalysis":
                    req.body = {"host": value}

                resp = requests.Session().send(request=req)
                if resp.ok:
                    responses[source.name] = service.parse_response(
                        resp, source.template
                    )
                else:
                    responses[source.name] = error_string
        return responses

    def ipaddress(self, value: str) -> str:
        if not ObservableType.from_observable_value(value) == ObservableType.IPV4:
            return ""
        return self._process_source(value, ObservableType.IPV4)

    def domain(self, value: str) -> str:
        if not ObservableType.from_observable_value(value) == ObservableType.DOMAIN:
            return ""
        return self._process_source(value, ObservableType.DOMAIN)

    def url(self, value: str) -> str:
        if not ObservableType.from_observable_value(value) == ObservableType.URL:
            return ""
        return self._process_source(value, ObservableType.URL)

    def email(self, value: str) -> str:
        if not ObservableType.from_observable_value(value) == ObservableType.EMAIL:
            return ""
        return self._process_source(value, ObservableType.EMAIL)
