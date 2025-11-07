from typing import Any, Dict
import requests_mock
import json

from domaintools.get_domain_reputation import DomaintoolsDomainReputation

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

ACTION = "domain_reputation"

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
                "domain_risk": {
                    "risk_score": 45,
                    "components": [
                        {"name": "proximity", "risk_score": 25},
                        {"name": "threat_profile", "risk_score": 20},
                    ],
                },
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


def test_get_domain_reputation_action_success():
    action = DomaintoolsDomainReputation()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI), json=DT_OUTPUT, additional_matcher=_qs_matcher({"domain": DOMAIN})
        )
        response = action.run({"domain": DOMAIN})

        assert response is not None
        data = response

        print("Result structure:", json.dumps(data, indent=2))

        assert data["results"][0]["domain"] == DOMAIN
        assert mock_requests.call_count == 1


def test_get_domain_reputation_action_api_error():
    action = DomaintoolsDomainReputation()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI),
            status_code=500,
            json={"error": {"message": "Internal Server Error"}},
            additional_matcher=_qs_matcher({"domain": DOMAIN}),
        )
        response = action.run({"domain": DOMAIN})

        print("Error response:", response)

        if response:
            data = response
            assert "error" in data or "Error" in str(data)
        else:
            assert not response

        assert mock_requests.call_count == 1


def test_get_domain_reputation_string_response():
    """Test that string responses are properly parsed to dict"""
    from unittest.mock import patch

    action = DomaintoolsDomainReputation()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a JSON string instead of dict
    json_string_response = json.dumps(DT_OUTPUT)

    with patch("domaintools.get_domain_reputation.DomaintoolsrunAction", return_value=json_string_response):
        result = action.run({"domain": DOMAIN})

        # Should be parsed back to dict
        assert isinstance(result, dict)
        assert result["response"]["results"][0]["domain"] is not None


def test_get_domain_reputation_dict_response():
    """Test that dict responses are returned as-is"""
    from unittest.mock import patch

    action = DomaintoolsDomainReputation()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a dict directly
    with patch("domaintools.get_domain_reputation.DomaintoolsrunAction", return_value=DT_OUTPUT):
        result = action.run({"domain": DOMAIN})

        # Should return dict as-is
        assert isinstance(result, dict)
        assert result == DT_OUTPUT


def test_get_domain_reputation_domaintools_error():
    """Test that DomainToolsError is handled properly"""
    from unittest.mock import patch
    from domaintools.models import DomainToolsError

    action = DomaintoolsDomainReputation()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise DomainToolsError
    with patch(
        "domaintools.get_domain_reputation.DomaintoolsrunAction", side_effect=DomainToolsError("Invalid API key")
    ):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "DomainTools client initialization error" in result["error"]


def test_get_domain_reputation_unexpected_exception():
    """Test that unexpected exceptions are handled properly"""
    from unittest.mock import patch

    action = DomaintoolsDomainReputation()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise a generic Exception
    with patch("domaintools.get_domain_reputation.DomaintoolsrunAction", side_effect=ValueError("Unexpected error")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "Unexpected initialization error" in result["error"]
