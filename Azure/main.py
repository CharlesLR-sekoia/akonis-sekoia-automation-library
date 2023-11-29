"""Entry point for connectors."""

from sekoia_automation.loguru.config import init_logging
from sekoia_automation.module import Module

from connectors.pull_azure_blob_data import AzureBlobConnector
from connectors.trigger_azure_eventhub import AzureEventsHubTrigger

if __name__ == "__main__":
    init_logging()

    module = Module()
    module.register(AzureEventsHubTrigger, "azure_eventhub_messages_trigger")
    module.register(AzureBlobConnector, "azure_blob_storage")
    module.run()
