# Security CLI

The `security-cli` is a CLI (and package) Python utility to perform common activities performed by security analysts.

`security-cli` main goal is to provide a standard interface for performing data enrichment, querying, lookups, scanning and more in a simple and straightforward CLI interface.

## Why?

I have been building workflows, playbooks, integrations and more to automate these processes throughout my career. Instead of continually having to understand how each product works, how to perform some action, etc. I wanted a simple CLI utility to do it all.

I know it's a lofty goal, but I believe we can build a sort of operating system framework which abstracts different product APIs into a single common framework/syntax.

This syntax is a common set of verbs which equates to HTTP calls with enough context.

This is the start of something great or horrible, time will tell. :)

## Features

The `security-cli` Python package and CLI tool to assist with abstracting third-party products from the different actions needing to be performed by a security analyst on a frequent basis.

Currently, the features are limited but the groundwork has been laid for many future improvements based on community feedback.

* Performs observable enrichment (enrich)
* Configuration (and environmental variables) driven mappings of actions, observable types and the different supported services

This is just the start of this project so it is limited in capabilities as I continue to build them out. That being said, the goal is the same; a simple and usable interface to perform common security operations activities.

For example, most APIs are overly complex and some even require multiple API calls to perform an action or gathering the correct data. `security-cli` provides a simple nomenclature based on common verbs within the security domain.

Currently, we only support the `enrich` action but more will be adopted as the project gains traction.

```bash
security-cli enrich {observable}
```

If this project gathers adoption, the plan is to extend it to support these additional common actions. These are currently not implemented.

```bash
security-cli scan {ip|host}
security-cli get {ip|host|name|id}
security-cli block {ip|host|nam}
security-cli query {logs|events|observables|identities|assets}
security-cli list {alerts|events|observables}

# Further in the future
security-cli create {host|identity|group|rule|case}
security-cli update {host|identity|group|rule|case} {**properties}
security-cli delete {host|identity|group|rule|case|host|ip|name|observables} {**properties}
security-cli respond {isolate|block|notify|approve|revoke}
security-cli validate {configuration|permissions}
security-cli trigger {workflow|playbook|ci}
security-cli monitor {event|case|workflow|playbook|ci}
security-cli assign {case|incident}

# Drive hypothesis driven discoveries
security-cli investigate {name|id}
```

### CLI

The CLI is simple, just run the following once installed.

> As features are added, this documentation will grow

```bash
poetry run security-cli enrich {SOME_OBSERVABLE}
```

Additionally, you can manage your config by using the `config` parameter.

```bash
poetry run security-cli config load
poetry run security-cli config get
```

### Supported Services

The following services and observable types are currently supported:

> If you have any suggestions or believe another service should be implemented, please create an issue or pull request!

| Name | API Key Required | Supports IP | Supports Domain | Supports URL | Supports Email |
|------|------------------|-------------|-----------------|--------------|----------------|
| VirusTotal | Yes        | Yes         | Yes             | Yes          | No             |
| HybridAnalysis | Yes    | Yes         | Yes             | Yes          | No             |
| AlienVault | Yes        | Yes         | Yes             | Yes          | No             |
| Shodan     | Yes        | Yes         | Yes             | Yes          | No             |
| Urlscan.io | Yes        | Yes         | Yes             | Yes          | No             |
| AbuseIPDB  | Yes        | Yes         | No              | No           | No             |
| HaveIBeenPwned | Yes    | No          | No              | No           | Yes            |

## Requirements

This project implements a custom [config.yaml.example](./config.yaml.example) file to determine which third-party enrichment services are supported for observable. These are mapped to different `actions`.

> Currently, `enrich` is the only supported action at this time.

### config.yaml

This project provides a custom configuration file and I believe it's pretty easy to understand.

First, copy the provided [config.yaml.example](config.yaml.example) config and remove the `.example` extension before using this service.

Within this configuration file there are [actions](#actions-configuration).

By default, all services supported are mapped to the current implemented enrichment `actions`. Currently, the only action type is `enrich` but other may be implemented in the future.

Under the `enrich` section we have the different supported observable types.

* ipaddress
* url
* domain
* email

> Additional hash types will be supported soon

That being said, each individual service can have a key named `apikey` and the API key value from that service but please consider not doing so.

You can set this keys value directly in the [config.yaml.example](config.yaml.example) but the preferred way is to use a `.env` or set the environmental variables directly.

> NOTE: It is highly recommended to set secrets as environmental variables when implementing this service. Stop storing secrets silly goose.

In order for this service to discover these variables, they must be in a specific format. Below is the list of currently supported variables:

* ENRICHMENT_MCP_VIRUSTOTAL_KEY
* ENRICHMENT_MCP_HYBRIDANALYSIS_KEY
* ENRICHMENT_MCP_ALIENVAULT_KEY
* ENRICHMENT_MCP_SHODAN_KEY
* ENRICHMENT_MCP_URLSCAN_KEY
* ENRICHMENT_MCP_ABUSEIPDB_KEY
* ENRICHMENT_MCP_HIBP_KEY

### Actions Configuration

Each enrichment in our config file resides under the `actions` key. Additionally, I have broken out the different types of enrichment that can be performed. This means, in the current implementation, we have a single action type called `enrich` but in the future this can be expanded for things like `scans` or `queries` etc.

Underneath these high-level actions, we list out the observable type followed by a list of services that support that type. The currently supported observable types are:

* ipaddress - ipv4 addresses
* domain - A domain or netloc
* url - A fully qualified URL with schema, etc.
* email - A standard email address

We also support these types but they are currently not implemented:

* md5 - A file MD5 hash
* sha1 - A file SHA1 hash
* sha256 - A file SHA256 hash

Each service must have a `name` and a `template`. The `apikey` field can be provided but we recommend to use environmental variables.

### Templates

Each service and observable type can have it's own template. These reside in the [templates](./templates/) directory and all templates are expected to exist here.

Each service defined has a template using jinja2 templates. You can modify these are needed, but the format of the filename must remain the same. 

These files have the following filename pattern.

```bash
{service.name}.{enrichment.type}.jinja2
```

> Ensure that the response object has the correct fields in the template itself or you will receive an error.

Below is an example output for `security-cli enrich 91.195.240.94` with some errors mixed in:

```python
{
    "virustotal": "error occurred looking up ip 91.195.240.94 in virustotal",
    "alienvault": "Service: alienvault\nIPAddress: \nReputation Score: 0\nTotal Votes: ",
    "shodan": "Service: shodan\nIPAddress: 91.195.240.94\nLast Analysis Results: 2025-04-25T21:02:52.644602\n\nTags\n\n\nAdditional information includes:\n\n* Latitude: 48.13743\n* Longitude: 11.57549\n* ASN: AS47846\n* Domains: ["servervps.net"]",
    "hybridanalysis": "error occurred looking up ip 91.195.240.94 in hybridanalysis",
    "urlscan": "Service: urlscan\nResult: https://urlscan.io/api/v1/result/01966efe-c8fa-74a4-bfc0-1ed479838e85/\n\nStats\n\n* uniqIPs - 6\n\n* uniqCountries - 2\n\n* dataLength - 432561\n\n* encodedDataLength - 218606\n\n* requests - 14\n\n\nPage\n* country - DE\n* server - Parking/1.0\n* ip - 91.195.240.94\n* mimeType - text/html\n* title - wearab.org\xa0-\xa0Informationen zum Thema wearab.\n* url - https://login.wearab.org/\n* tlsValidDays - 364\n* tlsAgeDays - 0\n* tlsValidFrom - 2025-04-25T00:00:00.000Z\n* domain - login.wearab.org\n* apexDomain - wearab.org\n* asnname - SEDO-AS SEDO GmbH, DE\n* asn - AS47846\n* tlsIssuer - Encryption Everywhere DV TLS CA - G2\n* status - 200\n",
    "abuseipdb": "Service: abuseripdb\nIPAddress: 91.195.240.94\nLast Analysis Result: 2025-03-30T14:04:45+00:00\nScore: 7\nUsage: Data Center/Web Hosting/Transit\nIs Tor: False\nIs Whitelisted: False\nISP: Sedo Domain Parking"
}
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.
