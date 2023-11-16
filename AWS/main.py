"""Initialize module and all connectors."""
from sekoia_automation.loguru.config import init_logging

from connectors import AwsModule
from connectors.s3.logs.trigger_cloudtrail_logs import CloudTrailLogsTrigger
from connectors.s3.logs.trigger_flowlog_records import FlowlogRecordsTrigger
from connectors.s3.trigger_s3_logs import AwsS3LogsTrigger
from connectors.s3.trigger_s3_parquet import AwsS3ParquetRecordsTrigger
from connectors.s3.trigger_s3_records import AwsS3RecordsTrigger
from connectors.trigger_sqs_messages import AwsSqsMessagesTrigger

if __name__ == "__main__":
    init_logging()

    module = AwsModule()

    module.register(CloudTrailLogsTrigger, "cloudtrail_logs_trigger")
    module.register(FlowlogRecordsTrigger, "flowlog_records_trigger")
    module.register(AwsS3LogsTrigger, "aws_s3_logs_trigger")
    module.register(AwsS3RecordsTrigger, "aws_s3_cloudtrail_records_trigger")
    module.register(AwsS3ParquetRecordsTrigger, "aws_s3_parquet_records_trigger")
    module.register(AwsSqsMessagesTrigger, "aws_sqs_messages_trigger")

    module.run()
