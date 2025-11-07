from typing import Any, Dict
import requests_mock
import json

from domaintools.get_reverse_domain import DomaintoolsReverseDomain

import datetime
import urllib.parse
import hmac
import hashlib

DOMAIN: str = "google.com"
HOST = "https://api.domaintools.com/"
URI = f"/v1/{DOMAIN}/hosting-history/"
API_KEY = "LOREM"
API_USERNAME = "IPSUM"
TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(api_username, api_key, timestamp, uri):
    params = "".join([api_username, timestamp, uri])
    return hmac.new(api_key.encode("utf-8"), params.encode("utf-8"), hashlib.sha1).hexdigest()


signature = sign(API_USERNAME, API_KEY, TIMESTAMP, URI)

ACTION = "reverse_domain"

DT_OUTPUT: dict[str, Any] = {
    "response": {
        "domain_name": "google.com",
        "ip_history": [
            {
                "domain": "GOOGLE.COM",
                "post_ip": "216.239.57.99",
                "pre_ip": None,
                "action": "N",
                "actiondate": "2004-04-24",
                "action_in_words": "New",
            },
            {
                "domain": "GOOGLE.COM",
                "post_ip": "66.102.7.99",
                "pre_ip": "216.239.57.99",
                "action": "C",
                "actiondate": "2004-05-08",
                "action_in_words": "Change",
            },
        ],
        "registrar_history": [],
        "nameserver_history": [],
    }
}


def test_get_reverse_domain_action_success():
    action = DomaintoolsReverseDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        # Mock the actual URL that will be called (including domain parameter)
        mock_requests.get(urllib.parse.urljoin(HOST, URI), json=DT_OUTPUT)
        result = action.run({"domain": DOMAIN})

        assert result is not None

        # Result is now a dict, no need to parse with json.loads()
        data = result

        assert data["ip_history"] is not None
        assert mock_requests.call_count == 1


def test_get_reverse_domain_action_api_error():
    action = DomaintoolsReverseDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    with requests_mock.Mocker() as mock_requests:
        mock_requests.get(
            urllib.parse.urljoin(HOST, URI), status_code=500, json={"error": {"message": "Internal Server Error"}}
        )
        result = action.run({"domain": DOMAIN})

        # Result is now a dict, no need to parse
        if result:
            data = result
            # Check if there's an error in the response
            assert "error" in data or "Error" in str(data)
        else:
            # If your action returns None/False on error
            assert not result

        assert mock_requests.call_count == 1


def test_get_reverse_domain_string_response():
    """Test that string responses are properly parsed to dict"""
    from unittest.mock import patch

    action = DomaintoolsReverseDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a JSON string instead of dict
    json_string_response = json.dumps(DT_OUTPUT)

    with patch("domaintools.get_reverse_domain.DomaintoolsrunAction", return_value=json_string_response):
        result = action.run({"domain": DOMAIN})

        # Should be parsed back to dict
        assert isinstance(result, dict)
        assert result["response"]["ip_history"] is not None


def test_get_reverse_domain_dict_response():
    """Test that dict responses are returned as-is"""
    from unittest.mock import patch

    action = DomaintoolsReverseDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to return a dict directly
    with patch("domaintools.get_reverse_domain.DomaintoolsrunAction", return_value=DT_OUTPUT):
        result = action.run({"domain": DOMAIN})

        # Should return dict as-is
        assert isinstance(result, dict)
        assert result == DT_OUTPUT


def test_get_reverse_domain_domaintools_error():
    """Test that DomainToolsError is handled properly"""
    from unittest.mock import patch
    from domaintools.models import DomainToolsError

    action = DomaintoolsReverseDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise DomainToolsError
    with patch("domaintools.get_reverse_domain.DomaintoolsrunAction", side_effect=DomainToolsError("Invalid API key")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "DomainTools client initialization error" in result["error"]


def test_get_reverse_domain_unexpected_exception():
    """Test that unexpected exceptions are handled properly"""
    from unittest.mock import patch

    action = DomaintoolsReverseDomain()
    action.module.configuration = {"api_key": API_KEY, "api_username": API_USERNAME, "host": HOST}

    # Mock DomaintoolsrunAction to raise a generic Exception
    with patch("domaintools.get_reverse_domain.DomaintoolsrunAction", side_effect=ValueError("Unexpected error")):
        result = action.run({"domain": DOMAIN})

        # Should return error dict
        assert isinstance(result, dict)
        assert "error" in result
        assert "Unexpected initialization error" in result["error"]
