# AWS Cloud Security Monitoring

A hands-on AWS security monitoring lab built to collect, detect, and investigate activity across cloud, host, and network layers.

The project uses CloudTrail, CloudWatch, VPC Flow Logs, EC2 telemetry, and a Python/Boto3 analyzer to turn AWS activity into useful security data.

## Architecture

- AWS CloudTrail for API and account activity
- CloudWatch Logs for centralized log collection
- CloudWatch metric filters and alarms for detections
- Ubuntu EC2 instance for host monitoring
- CloudWatch Agent for authentication and system logs
- VPC Flow Logs for network traffic visibility
- CloudWatch Logs Insights for investigation

## Security Detections

Current detections include:

- IAM security-related changes
- Security group changes
- Failed SSH authentication attempts

CloudWatch metric filters convert these events into security metrics and trigger alarms when matching activity occurs.

## Host and Network Monitoring

A dedicated Ubuntu EC2 instance sends authentication logs, system logs, and host metrics to CloudWatch.

VPC Flow Logs provide network-level visibility into accepted and rejected connections, allowing activity seen on the host to be compared with traffic observed at the VPC layer.

## Python Security Analyzer

`scripts/security_analyzer.py` automates SSH investigation using Python and Boto3.

The analyzer:

- Collects SSH authentication events from CloudWatch
- Queries VPC Flow Logs for SSH traffic
- Correlates activity by source IP
- Separates accepted and rejected connections
- Identifies failed and successful authentication
- Ranks sources generating rejected SSH traffic
- Generates timestamped security reports

The script supports configurable AWS region, log groups, monitored IP, and analysis window through environment variables.

## Example Analysis

A recent analysis window identified:

- 906 rejected SSH flows
- 482 unique rejected source IPs
- 21 accepted SSH flows

The analyzer then correlated allowed network traffic with authentication activity to distinguish legitimate access from unsolicited connection attempts.

## Project Status

The core monitoring pipeline and automated analyzer are operational.

Next steps:

- Document controlled detection tests
- Add investigation screenshots and sample reports
- Expand correlation and detection logic
