from urllib.parse import urlparse

from security_cli.enrich import ALL_LOOKUP_SERVICES


def test_service_get():
    """Tests that each service get method returns what is is supposed to.
    There are two edgecases in assert related to hybridanalysis URL pattern
    and urlscan URL generation when transforms to a domain format
    """
    for observable_type, service in ALL_LOOKUP_SERVICES.items():
        for name, enrichment in service.items():
            s = enrichment()
            sample = observable_type.get_sample_value()
            request = s.get(sample)
            assert (
                sample in request.url or 
                "search/terms" in request.url or
                urlparse(sample).netloc in request.url
            )
