import re
import socket
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

class Utils:

```
@staticmethod
def validate_domain(domain):

    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )

    return bool(
        pattern.match(domain)
    )

@staticmethod
def normalize_domain(domain):

    domain = domain.strip().lower()

    domain = domain.replace(
        "https://",
        ""
    )

    domain = domain.replace(
        "http://",
        ""
    )

    domain = domain.rstrip("/")

    return domain

@staticmethod
def is_valid_ip(ip):

    try:

        socket.inet_aton(ip)

        return True

    except socket.error:

        return False

@staticmethod
def resolve_ip(domain):

    try:

        return socket.gethostbyname(
            domain
        )

    except Exception:

        return None

@staticmethod
def current_timestamp():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

@staticmethod
def filename_timestamp():

    return datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

@staticmethod
def banner():

    console.print(
        Panel.fit(
            "[bold cyan]"
            "DOMAIN SECURITY ANALYZER"
            "[/bold cyan]\n"
            "[green]"
            "Linux + Windows Edition"
            "[/green]"
        )
    )

@staticmethod
def print_success(message):

    console.print(
        f"[bold green][+][/bold green] "
        f"{message}"
    )

@staticmethod
def print_error(message):

    console.print(
        f"[bold red][-][/bold red] "
        f"{message}"
    )

@staticmethod
def print_warning(message):

    console.print(
        f"[bold yellow][!][/bold yellow] "
        f"{message}"
    )

@staticmethod
def format_bytes(size):

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ]

    idx = 0

    while (
        size >= 1024
        and idx < len(units) - 1
    ):
        size /= 1024
        idx += 1

    return (
        f"{size:.2f} "
        f"{units[idx]}"
    )

@staticmethod
def safe_get(
    dictionary,
    key,
    default=None
):

    try:
        return dictionary.get(
            key,
            default
        )

    except Exception:
        return default
```

if **name** == "**main**":

```
Utils.banner()

print(
    Utils.validate_domain(
        "google.com"
    )
)

print(
    Utils.resolve_ip(
        "google.com"
    )
)

print(
    Utils.current_timestamp()
)
```
