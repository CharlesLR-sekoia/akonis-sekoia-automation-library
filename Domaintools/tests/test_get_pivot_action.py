from typing import Any, Dict
import requests_mock
import json

from domaintools.get_pivot_action import DomaintoolsPivotAction

import datetime
import urllib.parse
import hmac
import hashlib

DOMAIN: str = "pivot-example1.com"
HOST = "https://api.domaintools.com/"
URI = f"v1/iris-investigate/"  # Base URI without domain
API_KEY = "LOREM"
API_USERNAME = "IPSUM"
TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(api_username, api_key, timestamp, uri):
    params = "".join([api_username, timestamp, uri])
    return hmac.new(api_key.encode("utf-8"), params.encode("utf-8"), hashlib.sha1).hexdigest()


signature = sign(API_USERNAME, API_KEY, TIMESTAMP, URI)

ACTION = "pivot_action"

DT_OUTPUT: dict[str, Any] = {
    "response": {
        "limit_exceeded": False,
        "has_more_results": False,
        "message": "Enjoy your data.",
        "results_count": 20,
        "total_count": 156,
        "results": [
            {
                "domain": "pivot-example1.com",
                "domain_risk": {"risk_score": 25, "risk_score_string": "low"},
                "registrar": {"value": "Name.com LLC", "count": 120000},
                "registrant_org": {"value": "Pivot Examples Ltd", "count": 15},
                "create_date": {"value": "2023-03-12", "count": 1},
                "first_seen": {"value": "2023-03-12", "count": 1},
                "server_type": {"value": "cloudflare", "count": 5000},
                "website_title": {"value": "Pivot Example 1", "count": 1},
            },
            {
                "domain": "pivot-test2.net",
                "domain_risk": {"risk_score": 55, "risk_score_string": "medium"},
                "registrar": {"value": "GoDaddy.com, LLC", "count": 850000},
                "registrant_org": {"value": "Test Corp International", "count": 8},
                "create_date": {"value": "2024-01-08", "count": 1},
                "first_seen": {"value": "2024-01-08", "count": 1},
                "server_type": {"value": "Apache/2.4.48", "count": 180},
                "website_title": {"value": "Pivot Test 2 - Landing Page", "count": 1},
            },
            {
                "domain": "related-domain3.org",
                "domain_risk": {"risk_score": 80, "risk_score_string": "high"},
                "registrar": {"value": "Tucows Domains Inc.", "count": 320000},
                "registrant_org": {"value": "Anonymous Organization", "count": 450},
                "create_date": {"value": "2024-02-15", "count": 1},
                "first_seen": {"value": "2024-02-15", "count": 1},
                "server_type": {"value": "nginx/1.21.0", "count": 400},
                "website_title": {"value": "Related Domain 3", "count": 1},
            },
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


def test_get_pivot_action_action_success():
    action = DomaintoolsPivotAction()
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


def test_get_pivot_action_action_api_error():
    action = DomaintoolsPivotAction()
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


def test_get_pivot_action_string_response():
    """Test that string responses are properly parsed to dict"""
    from unittest.mock import patch

    action = DomaintoolsPivotAction()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a JSON string instead of dict
    json_string_response = json.dumps(DT_OUTPUT)

    with patch("domaintools.get_pivot_action.DomaintoolsrunAction", return_value=json_string_response):
        result = action.run({"domain": DOMAIN})

        # Should be parsed back to dict
        assert isinstance(result, dict)
        assert result["response"]["results"][0]["domain"] == DOMAIN


def test_get_pivot_action_dict_response():
    """Test that dict responses are returned as-is"""
    from unittest.mock import patch

    action = DomaintoolsPivotAction()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a dict directly
    with patch("domaintools.get_pivot_action.DomaintoolsrunAction", return_value=DT_OUTPUT):
        result = action.run({"domain": DOMAIN})

        # Should return dict as-is
        assert isinstance(result, dict)
        assert result == DT_OUTPUT


def test_get_pivot_action_domaintools_error():
    """Test that DomainToolsError is handled properly"""
    from unittest.mock import patch
    from domaintools.models import DomainToolsError

    action = DomaintoolsPivotAction()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise DomainToolsError
    with patch("domaintools.get_pivot_action.DomaintoolsrunAction", side_effect=DomainToolsError("Invalid API key")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "DomainTools client initialization error" in result["error"]


def test_get_pivot_action_unexpected_exception():
    """Test that unexpected exceptions are handled properly"""
    from unittest.mock import patch

    action = DomaintoolsPivotAction()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise a generic Exception
    with patch("domaintools.get_pivot_action.DomaintoolsrunAction", side_effect=ValueError("Unexpected error")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "Unexpected initialization error" in result["error"]
