from typing import Any, Dict
import requests_mock
import json

from domaintools.get_lookup_domain import DomaintoolsLookupDomain

import datetime
import urllib.parse
import hmac
import hashlib

DOMAIN: str = "example-test.com"
HOST = "https://api.domaintools.com/"
URI = f"v1/iris-investigate/"  # Base URI without domain
API_KEY = "LOREM"
API_USERNAME = "IPSUM"
TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(api_username, api_key, timestamp, uri):
    params = "".join([api_username, timestamp, uri])
    return hmac.new(api_key.encode("utf-8"), params.encode("utf-8"), hashlib.sha1).hexdigest()


signature = sign(API_USERNAME, API_KEY, TIMESTAMP, URI)

ACTION = "lookup_domain"

DT_OUTPUT: dict[str, Any] = {
    "response": {
        "limit_exceeded": False,
        "has_more_results": False,
        "message": "Enjoy your data.",
        "results_count": 1,
        "total_count": 1,
        "results": [
            {
                "domain": "example-test.com",
                "tld": "com",
                "active": True,
                "alexa": 125000,
                "adsense": {"value": "pub-1234567890", "count": 5},
                "google_analytics": {"value": "UA-12345678-1", "count": 10},
                "create_date": {"value": "2020-01-15", "count": 1},
                "expiration_date": {"value": "2025-01-15", "count": 1},
                "first_seen": {"value": "2020-01-20", "count": 1},
                "domain_risk": {"risk_score": 35},
                "registrar": {"value": "Example Registrar Inc.", "count": 50000},
                "registrar_status": [
                    "clientdeleteprohibited",
                    "clienttransferprohibited",
                    "clientupdateprohibited",
                    "serverdeleteprohibited",
                    "servertransferprohibited",
                    "serverupdateprohibited",
                ],
                "registrant_name": {"value": "John Doe", "count": 15},
                "registrant_org": {"value": "Example Corporation", "count": 25},
                "registrant_contact": {
                    "name": {"value": "John Doe", "count": 15},
                    "org": {"value": "Example Corporation", "count": 25},
                    "email": [{"value": "admin@example-test.com", "count": 5}],
                    "street": {"value": "123 Main Street", "count": 10},
                    "city": {"value": "Springfield", "count": 50},
                    "state": {"value": "IL", "count": 100},
                    "postal": {"value": "62701", "count": 20},
                    "country": {"value": "US", "count": 1000},
                    "phone": {"value": "+1.5551234567", "count": 8},
                    "fax": {"value": "", "count": 0},
                },
                "admin_contact": {
                    "name": {"value": "Jane Smith", "count": 10},
                    "org": {"value": "Example Corporation", "count": 25},
                    "email": [{"value": "admin@example-test.com", "count": 5}],
                    "city": {"value": "Springfield", "count": 50},
                    "country": {"value": "US", "count": 1000},
                    "phone": {"value": "+1.5551234567", "count": 8},
                },
                "technical_contact": {
                    "name": {"value": "Tech Support", "count": 30},
                    "org": {"value": "Example Hosting Ltd", "count": 100},
                    "email": [{"value": "tech@example-hosting.com", "count": 50}],
                    "city": {"value": "London", "count": 200},
                    "country": {"value": "GB", "count": 500},
                },
                "additional_whois_email": [{"value": "abuse@example-test.com", "count": 3}],
                "email_domain": [{"value": "example-test.com", "count": 5}],
                "soa_email": [{"value": "dns-admin@example-test.com", "count": 1}],
                "ip": [
                    {
                        "address": {"value": "192.0.2.10", "count": 15},
                        "asn": [{"value": "AS12345", "count": 1000}],
                        "country_code": {"value": "US", "count": 5000},
                        "isp": {"value": "Example ISP Inc", "count": 2000},
                    }
                ],
                "mx": [
                    {
                        "host": {"value": "mail.example-test.com", "count": 5},
                        "domain": {"value": "example-test.com", "count": 5},
                        "ip": [{"value": "192.0.2.20", "count": 10}],
                    }
                ],
                "name_server": [
                    {
                        "host": {"value": "ns1.example-dns.com", "count": 100},
                        "domain": {"value": "example-dns.com", "count": 50},
                        "ip": [{"value": "198.51.100.10", "count": 200}],
                    },
                    {
                        "host": {"value": "ns2.example-dns.com", "count": 100},
                        "domain": {"value": "example-dns.com", "count": 50},
                        "ip": [{"value": "198.51.100.11", "count": 200}],
                    },
                ],
                "server_type": {"value": "nginx/1.18.0", "count": 500},
                "website_title": {"value": "Example Test Website", "count": 1},
                "redirect": {"value": "https://www.example-test.com", "count": 1},
                "redirect_domain": {"value": "www.example-test.com", "count": 1},
                "ssl_info": [
                    {
                        "hash": {"value": "a1b2c3d4e5f67890abcdef1234567890abcdef12", "count": 1},
                        "subject": {"value": "CN=example-test.com", "count": 10},
                        "common_name": {"value": "example-test.com", "count": 10},
                        "issuer_common_name": {"value": "Let's Encrypt Authority X3", "count": 5000},
                        "organization": {"value": "Example Corporation", "count": 25},
                        "email": [{"value": "ssl@example-test.com", "count": 5}],
                        "alt_names": [
                            {"value": "www.example-test.com", "count": 5},
                            {"value": "mail.example-test.com", "count": 3},
                        ],
                        "not_before": {"value": "2024-01-01", "count": 1},
                        "not_after": {"value": "2024-04-01", "count": 1},
                        "duration": {"value": "90", "count": 1000},
                    }
                ],
                "tags": [{"label": "suspicious_domain", "scope": "organization", "tagged_at": "2024-01-15T10:30:00Z"}],
            }
        ],
    }
}


def _qs_matcher(expected_params: Dict[str, Any]):
    """
    returns a requests_mock additional_matcher that checks specific params in request.qs
    """

    def matcher(request):
        actual = {k: v[0] if isinstance(v, list) else v for k, v in request.qs.items()}
        # Check that all expected params are present with correct values
        for key, value in expected_params.items():
            if key not in actual or actual[key] != str(value):
                return False
        return True

    return matcher


def test_get_lookup_domain_action_success():
    action = DomaintoolsLookupDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        # Mock the actual URL that will be called (including domain parameter)
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI), json=DT_OUTPUT, additional_matcher=_qs_matcher({"domain": DOMAIN})
        )
        result = action.run({"domain": DOMAIN})

        assert result is not None

        # Result is now a dict, no need to parse with json.loads()
        data = result

        # Debug: print the actual structure
        print("Result structure:", json.dumps(data, indent=2))

        # Adjust assertion based on your actual return structure
        # If your action wraps the response, you might need something like:
        # assert data["Domain Reputation"]["results"][0]["domain"] == DOMAIN
        # Or if it returns the raw API response:
        assert data["results"][0]["domain"] == DOMAIN
        assert mock_requests.call_count == 1


def test_get_lookup_domain_action_api_error():
    action = DomaintoolsLookupDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI),
            status_code=500,
            json={"error": {"message": "Internal Server Error"}},
            additional_matcher=_qs_matcher({"domain": DOMAIN}),
        )
        result = action.run({"domain": DOMAIN})

        # Debug: print the actual result
        print("Error result:", result)

        # Result is now a dict, no need to parse
        if result:
            data = result
            # Check if there's an error in the response
            assert "error" in data or "Error" in str(data)
        else:
            # If your action returns None/False on error
            assert not result

        assert mock_requests.call_count == 1


def test_get_lookup_domain_string_response():
    """Test that string responses are properly parsed to dict"""
    from unittest.mock import patch

    action = DomaintoolsLookupDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a JSON string instead of dict
    json_string_response = json.dumps(DT_OUTPUT)

    with patch("domaintools.get_lookup_domain.DomaintoolsrunAction", return_value=json_string_response):
        result = action.run({"domain": DOMAIN})

        # Should be parsed back to dict
        assert isinstance(result, dict)
        assert result["response"]["results"][0]["domain"] == DOMAIN


def test_get_lookup_domain_dict_response():
    """Test that dict responses are returned as-is"""
    from unittest.mock import patch

    action = DomaintoolsLookupDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a dict directly
    with patch("domaintools.get_lookup_domain.DomaintoolsrunAction", return_value=DT_OUTPUT):
        result = action.run({"domain": DOMAIN})

        # Should return dict as-is
        assert isinstance(result, dict)
        assert result == DT_OUTPUT


def test_get_lookup_domain_domaintools_error():
    """Test that DomainToolsError is handled properly"""
    from unittest.mock import patch
    from domaintools.models import DomainToolsError

    action = DomaintoolsLookupDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise DomainToolsError
    with patch("domaintools.get_lookup_domain.DomaintoolsrunAction", side_effect=DomainToolsError("Invalid API key")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "DomainTools client initialization error" in result["error"]


def test_get_lookup_domain_unexpected_exception():
    """Test that unexpected exceptions are handled properly"""
    from unittest.mock import patch

    action = DomaintoolsLookupDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise a generic Exception
    with patch("domaintools.get_lookup_domain.DomaintoolsrunAction", side_effect=ValueError("Unexpected error")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "Unexpected initialization error" in result["error"]
