import json

import jinja2
import requests

from security_cli.enrich import ALL_LOOKUP_SERVICES


def test_config_manager():
    from security_cli.config import ConfigManager

    man = ConfigManager()
    man.load("./config.yaml")

    env = jinja2.Environment(loader=jinja2.FileSystemLoader("./src/security_cli/data/templates"))

    for observable_type, service in ALL_LOOKUP_SERVICES.items():
        for name, enrichment in service.items():
            for source in getattr(man._config.actions.enrich, observable_type.value):
                s = enrichment()
                s.template = env.get_template(f"{source.name}.{observable_type.value}.jinja2")
                if source.name == s.name:
                    data = json.load(open(man.get_abs_path(f"./tests/data/{source.name}.json")))
                    response = requests.Response()
                    response.status_code = 200
                    sample_value = observable_type.get_sample_value()
                    response.url = s.get(sample_value).url
                    response._content = json.dumps(data).encode('utf-8')

                    if source.name == "hibp":
                        resp_data = {"name": s.name, "email": sample_value, "response": data}
                        assert source.template.render(**resp_data) == s.parse_response(response, source.template)
                    elif isinstance(data, list):
                        data = data[0]
                    elif data.get("data") and not isinstance(data["data"], list):
                        data = data["data"]
                    if source.name == "urlscan":
                        data = data.get("results")[0]
                    if not isinstance(data, list):
                        data["name"] = s.name
                        assert source.template.render(**data) == s.parse_response(response, source.template)
