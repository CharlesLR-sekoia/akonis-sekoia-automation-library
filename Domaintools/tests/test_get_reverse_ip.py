from typing import Any, Dict
import requests_mock
import json

from domaintools.get_reverse_ip import DomaintoolsReverseIP

import datetime
import urllib.parse
import hmac
import hashlib

IP: str = "78.47.233.218"
HOST = "https://api.domaintools.com/"
URI = f"v1/iris-investigate/"  # Base URI without domain
API_KEY = "LOREM"
API_USERNAME = "IPSUM"
TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(api_username, api_key, timestamp, uri):
    params = "".join([api_username, timestamp, uri])
    return hmac.new(api_key.encode("utf-8"), params.encode("utf-8"), hashlib.sha1).hexdigest()


signature = sign(API_USERNAME, API_KEY, TIMESTAMP, URI)

DT_OUTPUT: dict[str, Any] = {
    "response": {
        "limit_exceeded": False,
        "has_more_results": False,
        "message": "Enjoy your data.",
        "results_count": 10,
        "total_count": 25,
        "results": [
            {
                "domain": "example-site1.com",
                "domain_risk": {"risk_score": 15},
                "first_seen": {"value": "2023-06-10T11:55:34Z", "count": 1},
                "server_type": {"value": "Apache/2.4.41", "count": 100},
                "website_title": {"value": "Example Site 1 - Home", "count": 1},
            },
            {
                "domain": "example-site2.net",
                "domain_risk": {"risk_score": 65},
                "first_seen": {"value": "2024-01-05T11:55:34Z", "count": 1},
                "server_type": {"value": "cloudflare", "count": 250},
                "website_title": {"value": "Example Site 2", "count": 1},
            },
            {
                "domain": "test-domain3.org",
                "domain_risk": {"risk_score": 30},
                "first_seen": {"value": "2022-11-20T11:55:34Z", "count": 1},
                "server_type": {"value": "Apache/2.4.41", "count": 100},
                "website_title": {"value": "Test Domain Organization", "count": 1},
            },
            {
                "domain": "demo-website4.com",
                "domain_risk": {"risk_score": 8},
                "first_seen": {"value": "2021-08-15T11:55:34Z", "count": 1},
                "server_type": {"value": "nginx/1.18.0", "count": 300},
                "website_title": {"value": "Demo Website 4 - Showcase", "count": 1},
            },
            {
                "domain": "sample-page5.io",
                "domain_risk": {"risk_score": 42},
                "first_seen": {"value": "2023-09-22T11:55:34Z", "count": 1},
                "server_type": {"value": "cloudflare", "count": 5000},
                "website_title": {"value": "Sample Page 5", "count": 1},
            },
            {
                "domain": "web-portal6.info",
                "domain_risk": {"risk_score": 18},
                "first_seen": {"value": "2020-03-10T11:55:34Z", "count": 1},
                "server_type": {"value": "Apache/2.4.46", "count": 180},
                "website_title": {"value": "Web Portal 6 - Information Hub", "count": 1},
            },
            {
                "domain": "online-service7.app",
                "domain_risk": {"risk_score": 70},
                "first_seen": {"value": "2024-02-28T11:55:34Z", "count": 1},
                "server_type": {"value": "nginx/1.21.6", "count": 400},
                "website_title": {"value": "Online Service 7", "count": 1},
            },
            {
                "domain": "digital-platform8.tech",
                "domain_risk": {"risk_score": 22},
                "first_seen": {"value": "2022-05-18T11:55:34Z", "count": 1},
                "server_type": {"value": "nginx/1.19.10", "count": 320},
                "website_title": {"value": "Digital Platform 8 - Tech Solutions", "count": 1},
            },
            {
                "domain": "cloud-solution9.dev",
                "domain_risk": {"risk_score": 35},
                "first_seen": {"value": "2023-11-05T11:55:34Z", "count": 1},
                "server_type": {"value": "Apache/2.4.52", "count": 200},
                "website_title": {"value": "Cloud Solution 9 - Development", "count": 1},
            },
            {
                "domain": "virtual-office10.space",
                "domain_risk": {"risk_score": 12},
                "first_seen": {"value": "2021-12-01T11:55:34Z", "count": 1},
                "server_type": {"value": "Microsoft-IIS/10.0", "count": 50},
                "website_title": {"value": "Virtual Office 10 - Workspace", "count": 1},
            },
        ],
    }
}


def test_get_reverse_ip_action_success():
    action = DomaintoolsReverseIP()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        # Mock the actual URL that will be called (including domain parameter)
        # /!\ DOMAIN is not sent in params but in the URL path /!\
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI),
            json=DT_OUTPUT,
        )
        # result = action.run({"domain": DOMAIN})
        result = action.run({"ip": IP})

        assert result is not None

        # Result is now a dict, no need to parse with json.loads()
        data = result

        # Debug: print the actual structure
        print("Result structure:", json.dumps(data, indent=2))

        # assert data["ip_addresses"] is not None
        assert mock_requests.call_count == 1


def test_get_reverse_ip_action_api_error():
    action = DomaintoolsReverseIP()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI), status_code=500, json={"error": {"message": "Internal Server Error"}}
        )
        # result = action.run({"domain": DOMAIN})
        result = action.run({"ip": IP})

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


def test_get_reverse_ip_string_response():
    """Test that string responses are properly parsed to dict"""
    from unittest.mock import patch

    action = DomaintoolsReverseIP()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a JSON string instead of dict
    json_string_response = json.dumps(DT_OUTPUT)

    with patch("domaintools.get_reverse_ip.DomaintoolsrunAction", return_value=json_string_response):
        result = action.run({"ip": IP})

        # Should be parsed back to dict
        assert isinstance(result, dict)
        assert result["response"]["results"] is not None


def test_get_reverse_ip_dict_response():
    """Test that dict responses are returned as-is"""
    from unittest.mock import patch

    action = DomaintoolsReverseIP()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a dict directly
    with patch("domaintools.get_reverse_ip.DomaintoolsrunAction", return_value=DT_OUTPUT):
        result = action.run({"ip": IP})

        # Should return dict as-is
        assert isinstance(result, dict)
        assert result == DT_OUTPUT


def test_get_reverse_ip_domaintools_error():
    """Test that DomainToolsError is handled properly"""
    from unittest.mock import patch
    from domaintools.models import DomainToolsError

    action = DomaintoolsReverseIP()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise DomainToolsError
    with patch("domaintools.get_reverse_ip.DomaintoolsrunAction", side_effect=DomainToolsError("Invalid API key")):
        result = action.run({"ip": IP})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "DomainTools client initialization error" in result["error"]


def test_get_reverse_ip_unexpected_exception():
    """Test that unexpected exceptions are handled properly"""
    from unittest.mock import patch

    action = DomaintoolsReverseIP()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise a generic Exception
    with patch("domaintools.get_reverse_ip.DomaintoolsrunAction", side_effect=ValueError("Unexpected error")):
        result = action.run({"ip": IP})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "Unexpected initialization error" in result["error"]
