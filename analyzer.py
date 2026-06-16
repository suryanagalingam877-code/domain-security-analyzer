from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress

from modules.dns_scanner import DNSScanner
from modules.ssl_scanner import SSLScanner
from modules.tls_scanner import TLSScanner
from modules.subdomain_scanner import SubdomainScanner
from modules.headers_scanner import HeadersScanner
from modules.whois_scanner import WhoisScanner
from modules.dmarc_scanner import DmarcScanner
from modules.dkim_scanner import DKIMScanner
from modules.dnssec_scanner import DNSSECScanner
from modules.caa_scanner import CAAScanner
from modules.report_generator import ReportGenerator


console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]DOMAIN SECURITY ANALYZER[/bold cyan]\n"
            "[green]Linux + Windows Edition[/green]"
        )
    )


def main():

    banner()

    domain = Prompt.ask(
        "[bold yellow]Enter Domain[/bold yellow]"
    ).strip()

    results = {}

    with Progress() as progress:

        task = progress.add_task(
            "[cyan]Scanning...",
            total=10
        )

        results["dns"] = DNSScanner(domain).scan()
        progress.advance(task)

        results["dmarc"] = DmarcScanner(domain).scan()
        progress.advance(task)

        results["dkim"] = DKIMScanner(domain).scan()
        progress.advance(task)

        results["dnssec"] = DNSSECScanner(domain).scan()
        progress.advance(task)

        results["caa"] = CAAScanner(domain).scan()
        progress.advance(task)

        results["ssl"] = SSLScanner(domain).scan()
        progress.advance(task)

        results["tls"] = TLSScanner(domain).scan()
        progress.advance(task)

        results["headers"] = HeadersScanner(domain).scan()
        progress.advance(task)

        results["whois"] = WhoisScanner(domain).scan()
        progress.advance(task)

        results["subdomains"] = SubdomainScanner(domain).scan()
        progress.advance(task)

    report = ReportGenerator(
        domain,
        results
    ).generate()

    console.print(
        "\n[bold green]Scan Complete[/bold green]"
    )

    console.print(
        f"\n[cyan]JSON Report:[/cyan] "
        f"{report['json_report']}"
    )

    console.print(
        f"[cyan]HTML Report:[/cyan] "
        f"{report['html_report']}"
    )


if __name__ == "__main__":
    main()