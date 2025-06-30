from abc import abstractmethod
from typing import TypeVar, Callable

import requests

from .abuseipdb import AbuseIPDBIP
from .alienvault import AlienVaultDomain, AlienVaultIP
from .hibp import HaveIBeenPwnedEmail
from .hybridanalysis import HybridAnalysisDomain, HybridAnalysisIP
from .shodan import ShodanDomain, ShodanIP
from .urlscan import UrlscanDomain, UrlscanIP, UrlscanUrl
from .virustotal import VirusTotalDomain, VirusTotalIP, VirusTotalFile, VirusTotalURL


EnrichmentService = TypeVar("EnrichmentService", "SupportedService", Callable)


class SupportedService:

    @abstractmethod
    def get(self, value: str) -> requests.PreparedRequest:
        raise NotImplementedError(
            f"the service for this value '{value}' is not supported."
        )

    @abstractmethod
    def parse_response(self, response: requests.Response) -> str:
        raise NotImplementedError(
            f"the service for this url '{response.url}' is not supported."
        )
