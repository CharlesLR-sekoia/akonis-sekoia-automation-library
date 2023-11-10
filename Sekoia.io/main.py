# flake8: noqa: E402
from sekoiaio.utils import should_patch

if should_patch():
    from gevent import monkey

    monkey.patch_all()

from sekoia_automation.module import Module

from sekoiaio.intelligence_center import CreateNewTrackerNotification, PostReportsPdf, PostReportsUrl, ReportsGetReport
from sekoiaio.intelligence_center.actions import PostBundleAction, GetContextAction
from sekoiaio.intelligence_center.upload_observables_inthreat import UploadObservablesAction
from sekoiaio.operation_center import (
    ActivateCountermeasure,
    AddsAttributeToAsset,
    AddsKeyToAsset,
    AssociateNewAlertsOnCase,
    CreatesNewAsset,
    DeletesAsset,
    DenyCountermeasure,
    GetAlert,
    ListAlerts,
    ListAssets,
    PatchAlert,
    PostCommentOnAlert,
    PredictStateOfAlert,
    ReturnsAsset,
    TriggerActionOnAlertWorkflow,
)
from sekoiaio.operation_center.get_aggregation_query import GetAggregationQuery
from sekoiaio.operation_center.get_event_field_common_values import GetEventFieldCommonValues
from sekoiaio.operation_center.get_events import GetEvents
from sekoiaio.operation_center.push_event_to_intake import PushEventToIntake
from sekoiaio.triggers.alerts import (
    AlertCommentCreatedTrigger,
    AlertCreatedTrigger,
    AlertStatusChangedTrigger,
    AlertUpdatedTrigger,
    SecurityAlertsTrigger,
)
from sekoiaio.triggers.intelligence import FeedConsumptionTrigger, FeedIOCConsumptionTrigger

if __name__ == "__main__":
    module = Module()

    module.register(ActivateCountermeasure, "patch-alerts/countermeasures/{cm_uuid}/activate")
    module.register(AddsAttributeToAsset, "post-assets/{uuid}/attr")
    module.register(AddsKeyToAsset, "post-assets/{uuid}/keys")
    module.register(AssociateNewAlertsOnCase, "patch-cases/{case_uuid}/alerts")
    module.register(CreatesNewAsset, "post-assets")
    module.register(DenyCountermeasure, "patch-alerts/countermeasures/{cm_uuid}/deny")
    module.register(GetAlert, "get-alerts/{uuid}")
    module.register(CreateNewTrackerNotification, "post-trackers/notifications/")
    module.register(PostBundleAction, "post_bundle")
    module.register(GetContextAction, "get_context")
    module.register(UploadObservablesAction, "upload_observables_inthreat")
    module.register(ListAlerts, "get-alerts")
    module.register(PatchAlert, "patch-alerts/{uuid}")
    module.register(PostCommentOnAlert, "post-alerts/{uuid}/comments")
    module.register(PostReportsPdf, "post-reports/pdf")
    module.register(PostReportsUrl, "post-reports/url")
    module.register(PredictStateOfAlert, "post-alert")
    module.register(ReportsGetReport, "get-reports/{uuid}")
    module.register(GetEventFieldCommonValues, "get-event-field-common-values")
    module.register(GetEvents, "get-events")
    module.register(TriggerActionOnAlertWorkflow, "patch-alerts/{uuid}/workflow")
    module.register(PushEventToIntake, "push-events-to-intake")
    module.register(ListAssets, "get-assets")
    module.register(DeletesAsset, "delete-assets/{uuid}")
    module.register(ReturnsAsset, "get-assets/{uuid}")
    module.register(GetAggregationQuery, "get-aggregation-query")

    # Operation Center Triggers
    module.register(SecurityAlertsTrigger, "security_alerts_trigger")
    module.register(AlertCreatedTrigger, "alert_created_trigger")
    module.register(AlertUpdatedTrigger, "alert_updated_trigger")
    module.register(AlertStatusChangedTrigger, "alert_status_changed_trigger")
    module.register(AlertCommentCreatedTrigger, "alert_comment_created_trigger")

    # Intelligence Center Triggers
    module.register(FeedConsumptionTrigger, "feed_consumption_trigger")
    module.register(FeedIOCConsumptionTrigger, "feed_ioc_consumption_trigger")

    module.run()
