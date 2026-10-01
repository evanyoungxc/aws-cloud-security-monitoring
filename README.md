# AWS Cloud Security Monitoring

A hands-on AWS security monitoring project focused on collecting and analyzing cloud, host, and network telemetry.

The environment uses AWS CloudTrail, CloudWatch, VPC Flow Logs, and an Ubuntu EC2 monitoring instance to provide visibility across multiple layers of an AWS environment.

## Current Architecture

- AWS CloudTrail for API and account activity
- CloudWatch Logs for centralized log collection
- CloudWatch metric filters and alarms for security detections
- Ubuntu EC2 instance for host-level monitoring
- CloudWatch Agent for system and authentication logs
- VPC Flow Logs for network traffic visibility
- CloudWatch Logs Insights for log investigation

## Current Detections

The environment currently monitors for:

- IAM security-related changes
- Security group changes
- Failed SSH authentication attempts

These events are converted into CloudWatch metrics and used to trigger alarms when security-relevant activity is detected.

## Host Monitoring

A dedicated Ubuntu EC2 instance sends host telemetry to CloudWatch using the CloudWatch Agent, including:

- Authentication logs
- System logs
- Host performance metrics

SSH access is configured to require both public-key and password authentication.

## Network Monitoring

VPC Flow Logs collect network metadata across the lab VPC, including accepted and rejected connections.

CloudWatch Logs Insights is used to investigate traffic patterns such as rejected connection attempts and targeted destination ports.

## Project Status

The monitoring and log collection infrastructure is operational.

Planned next steps include:

- Correlating VPC Flow Logs with host authentication events
- Building repeatable CloudWatch Logs Insights investigations
- Automating security analysis with Python and Boto3
- Documenting controlled security events and investigations
