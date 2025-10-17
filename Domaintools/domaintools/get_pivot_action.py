from typing import Any
import json
from sekoia_automation.action import Action
from .models import DomainToolsConfig, DomainToolsError, DomaintoolsrunAction

class DomaintoolsPivotAction(Action):
    def run(self, arguments: dict[str, Any]) -> dict:
        try:
            config = DomainToolsConfig(
                api_username=self.module.configuration["api_username"],
                api_key=self.module.configuration["api_key"],
                host="https://api.domaintools.com/"
            )

            parsed_args: dict[str, Any] = {
                "domain": arguments.get("domain"),
                "ip": arguments.get("ip"),
                "email": arguments.get("email"),
                "domaintools_action": "pivot_action",
            }

            response = DomaintoolsrunAction(config, parsed_args)

            # Parse the JSON string into a dict for Sekoia SDK validation
            if isinstance(response, str):
                return json.loads(response)
            return response

        except DomainToolsError as e:
            return {"error": f"DomainTools client initialization error: {e}"}
        except Exception as e:
            return {"error": f"Unexpected initialization error: {e}"}
