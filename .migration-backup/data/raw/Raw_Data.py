import csv
import random
import uuid
from datetime import datetime, timedelta

TOTAL_RECORDS = 1_000_000
OUTPUT_FILE = "Cyber_Incident_Timeline_Raw_Data_1Million.csv"

LOG_SOURCES = ["Windows", "Linux", "Firewall"]

EVENTS = {
    "Windows": [
        ("4624", "Successful Login"),
        ("4625", "Failed Login"),
        ("4672", "Special Privileges Assigned"),
        ("4688", "Process Created"),
        ("4720", "User Account Created"),
    ],
    "Linux": [
        ("AUTH-001", "SSH Login"),
        ("AUTH-002", "SSH Failed Login"),
        ("AUTH-003", "Sudo Command"),
        ("SYS-001", "Process Started"),
        ("SYS-003", "File Modified"),
    ],
    "Firewall": [
        ("FW-001", "Allowed Connection"),
        ("FW-002", "Blocked Connection"),
        ("FW-003", "Port Scan"),
        ("FW-004", "DNS Request"),
        ("FW-007", "SSH Connection"),
    ],
}

USERS = [
    "admin", "root", "alice", "bob",
    "analyst", "developer", "guest"
]

HOSTNAMES = [
    "DC-01", "WEB-01", "DB-01", "APP-01",
    "FILE-01", "WORKSTATION-01",
    "FIREWALL-01", "LINUX-SERVER-01"
]

PROTOCOLS = [
    "TCP", "UDP", "ICMP",
    "HTTP", "HTTPS", "SSH", "RDP", "DNS"
]

SEVERITIES = [
    "Informational", "Low",
    "Medium", "High", "Critical"
]

ACTIONS = [
    "Allowed", "Blocked", "Accepted",
    "Rejected", "Failed", "Successful"
]

PROCESS_NAMES = [
    "svchost.exe", "powershell.exe",
    "cmd.exe", "sshd", "nginx",
    "postgres", "python", "bash", "-"
]

FILE_NAMES = [
    "config.txt", "system.log",
    "security.log", "database.db",
    "backup.zip", "report.pdf",
    "access.log", "data.json", "-"
]

PORTS = [
    21, 22, 25, 53, 80,
    110, 143, 443, 445,
    3306, 3389, 5432, 8080
]

FIELDS = [
    "event_id_unique",
    "timestamp",
    "log_source",
    "event_id",
    "event_type",
    "severity",
    "action",
    "username",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "hostname",
    "session_id",
    "correlation_id",
    "process_name",
    "file_name",
    "file_hash"
]

START_DATE = datetime(2026, 1, 1)
END_DATE = datetime(2026, 12, 31, 23, 59, 59)

TOTAL_SECONDS = int(
    (END_DATE - START_DATE).total_seconds()
)


def random_private_ip():

    option = random.randint(1, 3)

    if option == 1:
        return (
            f"10.{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}"
        )

    elif option == 2:
        return (
            f"172.{random.randint(16,31)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}"
        )

    return (
        f"192.168."
        f"{random.randint(0,255)}."
        f"{random.randint(1,254)}"
    )


def random_public_ip():

    prefix = random.choice([
        "192.0.2",
        "198.51.100",
        "203.0.113"
    ])

    return f"{prefix}.{random.randint(1,254)}"


def random_source_ip():

    if random.random() < 0.5:
        return random_private_ip()

    return random_public_ip()


def random_timestamp():

    random_seconds = random.randint(
        0,
        TOTAL_SECONDS
    )

    timestamp = (
        START_DATE
        + timedelta(seconds=random_seconds)
    )

    return timestamp.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow(FIELDS)

    for i in range(
        1,
        TOTAL_RECORDS + 1
    ):

        log_source = random.choice(
            LOG_SOURCES
        )

        event_id, event_type = random.choice(
            EVENTS[log_source]
        )

        username = (
            "-"
            if log_source == "Firewall"
            else random.choice(USERS)
        )

        row = [

            f"EVT-{i:08d}",

            random_timestamp(),

            log_source,

            event_id,

            event_type,

            random.choice(
                SEVERITIES
            ),

            random.choice(
                ACTIONS
            ),

            username,

            random_source_ip(),

            random_private_ip(),

            random.randint(
                1024,
                65535
            ),

            random.choice(
                PORTS
            ),

            random.choice(
                PROTOCOLS
            ),

            random.choice(
                HOSTNAMES
            ),

            uuid.uuid4().hex[:16],

            "INC-"
            + uuid.uuid4().hex[:10].upper(),

            random.choice(
                PROCESS_NAMES
            ),

            random.choice(
                FILE_NAMES
            ),

            uuid.uuid4().hex
            + uuid.uuid4().hex
        ]

        writer.writerow(row)

        if i % 100000 == 0:

            print(
                f"{i:,} records generated"
            )


print("\nCompleted!")

print(
    "File created:",
    OUTPUT_FILE
)

print(
    "Total rows:",
    f"{TOTAL_RECORDS:,}"
)

print(
    "Total columns:",
    len(FIELDS)
)