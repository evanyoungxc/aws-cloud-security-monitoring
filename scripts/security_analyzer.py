from pathlib import Path
import boto3
import os
import re
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict

REGION = os.getenv("AWS_REGION", "us-east-1")

AUTH_LOG_GROUP = os.getenv(
    "AUTH_LOG_GROUP",
    "/security-monitoring/ec2/auth"
)

FLOW_LOG_GROUP = os.getenv(
    "FLOW_LOG_GROUP",
    "/security-monitoring/vpc-flow-logs"
)

MONITORED_IP = os.getenv("MONITORED_IP", "172.31.28.205")
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "336"))

logs = boto3.client("logs", region_name=REGION)


def analyze_ssh_auth():
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    paginator = logs.get_paginator("filter_log_events")

    activity = defaultdict(
        lambda: {
            "failed": 0,
            "password": 0,
            "publickey": 0
        }
    )

    for page in paginator.paginate(
        logGroupName=AUTH_LOG_GROUP,
        startTime=int(start_time.timestamp() * 1000),
        endTime=int(end_time.timestamp() * 1000),
        filterPattern="sshd"
    ):
        for event in page.get("events", []):
            message = event["message"]

            match = re.search(
                r"from (\d+\.\d+\.\d+\.\d+)",
                message
            )

            if not match:
                continue

            ip = match.group(1)

            if "Failed password" in message:
                activity[ip]["failed"] += 1

            elif "Accepted password" in message:
                activity[ip]["password"] += 1

            elif "Accepted publickey" in message:
                activity[ip]["publickey"] += 1

    return activity


def analyze_ssh_flows():
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    flows = defaultdict(
        lambda: {
            "accept": 0,
            "reject": 0
        }
    )

    def run_flow_query(action):
        query = rf"""
fields @message
| parse @message /(?<v>\S+) (?<acct>\S+) (?<eni>\S+) (?<src>\S+) (?<dst>\S+) (?<sport>\S+) (?<dport>\S+) (?<proto>\S+) (?<pkt>\S+) (?<byteCount>\S+) (?<flowStart>\S+) (?<flowEnd>\S+) (?<flowAction>\S+) (?<flowStatus>\S+)/
| filter dst = "{MONITORED_IP}"
| filter dport = "22"
| filter proto = "6"
| filter flowAction = "{action}"
| stats count(*) as total by src
| sort total desc
"""

        response = logs.start_query(
            logGroupName=FLOW_LOG_GROUP,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query
        )

        query_id = response["queryId"]

        while True:
            result = logs.get_query_results(queryId=query_id)

            if result["status"] == "Complete":
                return result["results"]

            if result["status"] in [
                "Failed",
                "Cancelled",
                "Timeout",
                "Unknown"
            ]:
                raise RuntimeError(
                    f"{action} query ended with status: "
                    f"{result['status']}"
                )

            time.sleep(1)

    for action in ["ACCEPT", "REJECT"]:
        results = run_flow_query(action)

        for row in results:
            record = {
                item["field"]: item["value"]
                for item in row
            }

            ip = record.get("src")

            if not ip:
                continue

            total = int(float(record.get("total", 0)))

            if action == "ACCEPT":
                flows[ip]["accept"] = total
            else:
                flows[ip]["reject"] = total

    return flows


def print_report(auth, flows):
    print("\n=== AWS SECURITY MONITORING REPORT ===\n")

    # Authentication totals
    failed_total = sum(x["failed"] for x in auth.values())
    password_total = sum(x["password"] for x in auth.values())
    publickey_total = sum(x["publickey"] for x in auth.values())

    # Network totals
    total_accept = sum(x["accept"] for x in flows.values())
    total_reject = sum(x["reject"] for x in flows.values())
    unique_rejected = sum(
        1 for x in flows.values()
        if x["reject"] > 0
    )

    print("SSH Authentication Summary")
    print("--------------------------")
    print(f"Failed passwords:        {failed_total}")
    print(f"Accepted passwords:      {password_total}")
    print(f"Accepted public keys:    {publickey_total}")

    print("\nNetwork Security Summary")
    print("------------------------")
    print(f"Accepted SSH flows:      {total_accept}")
    print(f"Rejected SSH flows:      {total_reject}")
    print(f"Unique rejected sources: {unique_rejected}")

    print("\nTop 10 Rejected SSH Sources")
    print("---------------------------")

    rejected = [
        (ip, data["reject"])
        for ip, data in flows.items()
        if data["reject"] > 0
    ]

    rejected.sort(key=lambda x: x[1], reverse=True)

    print(f"{'Source IP':<20}{'Rejected Flows':<15}")
    print("-" * 35)

    for ip, count in rejected[:10]:
        print(f"{ip:<20}{count:<15}")

    print("\nAuthenticated / Allowed Sources")
    print("-------------------------------")

    print(
        f"{'Source IP':<18}"
        f"{'ACCEPT':<9}"
        f"{'REJECT':<9}"
        f"{'Failed':<9}"
        f"{'Password':<11}"
        f"{'PublicKey':<10}"
    )

    print("-" * 66)

    all_ips = set(auth) | set(flows)

    important_ips = []

    for ip in all_ips:
        a = auth.get(
            ip,
            {"failed": 0, "password": 0, "publickey": 0}
        )

        f = flows.get(
            ip,
            {"accept": 0, "reject": 0}
        )

        if (
            f["accept"] > 0
            or a["failed"] > 0
            or a["password"] > 0
            or a["publickey"] > 0
        ):
            important_ips.append(ip)

    for ip in sorted(important_ips):
        a = auth.get(
            ip,
            {"failed": 0, "password": 0, "publickey": 0}
        )

        f = flows.get(
            ip,
            {"accept": 0, "reject": 0}
        )

        print(
            f"{ip:<18}"
            f"{f['accept']:<9}"
            f"{f['reject']:<9}"
            f"{a['failed']:<9}"
            f"{a['password']:<11}"
            f"{a['publickey']:<10}"
        )


if __name__ == "__main__":
    import io
    from contextlib import redirect_stdout

    print("Querying authentication logs...")
    auth_activity = analyze_ssh_auth()

    print("Querying VPC Flow Logs...")
    flow_activity = analyze_ssh_flows()

    # Capture the finished report
    report_buffer = io.StringIO()

    with redirect_stdout(report_buffer):
        print_report(auth_activity, flow_activity)

    report_text = report_buffer.getvalue()

    # Display report in terminal
    print(report_text, end="")

    # Save timestamped report
    reports_dir = Path.home() / "security-analyzer/reports"
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_UTC")
    report_path = reports_dir / f"security-report_{timestamp}.txt"

    report_path.write_text(report_text)

    print(f"\nReport saved to: {report_path}")
