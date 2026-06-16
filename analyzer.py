from rich.console import Console
from rich.panel import Panel

from ui.terminal_ui import TerminalUI

from core.dns_scanner import DNSScanner
from core.ssl_scanner import SSLScanner
from core.tls_scanner import TLSScanner
from core.dmarc_scanner import DmarcScanner
from core.dkim_scanner import DKIMScanner
from core.dnssec_scanner import DNSSECScanner
from core.caa_scanner import CAAScanner
from core.headers_scanner import HeadersScanner
from core.whois_scanner import WhoisScanner
from core.subdomain_scanner import SubdomainScanner
from core.report_generator import ReportGenerator


console = Console()


def run_scan(domain, ui):

    results = {}

    modules = [
        ("DNS", DNSScanner),
        ("DMARC", DmarcScanner),
        ("DKIM", DKIMScanner),
        ("DNSSEC", DNSSECScanner),
        ("CAA", CAAScanner),
        ("SSL", SSLScanner),
        ("TLS", TLSScanner),
        ("HEADERS", HeadersScanner),
        ("WHOIS", WhoisScanner),
        ("SUBDOMAINS", SubdomainScanner)
    ]

    with ui.progress_bar() as progress:

        task = progress.add_task(
            "[cyan]Scanning Target...",
            total=len(modules)
        )

        for name, scanner in modules:

            try:

                results[
                    name.lower()
                ] = scanner(
                    domain
                ).scan()

            except Exception as e:

                results[
                    name.lower()
                ] = {
                    "error": str(e)
                }

            progress.advance(task)

    return results


def calculate_score(results):

    score = 0

    try:

        if results.get(
            "dmarc",
            {}
        ).get(
            "record_found"
        ):
            score += 15

        if results.get(
            "dkim",
            {}
        ).get(
            "dkim_enabled"
        ):
            score += 15

        if results.get(
            "dnssec",
            {}
        ).get(
            "dnssec_enabled"
        ):
            score += 15

        if results.get(
            "caa",
            {}
        ).get(
            "caa_enabled"
        ):
            score += 10

        if results.get(
            "ssl",
            {}
        ).get(
            "ssl_available"
        ):
            score += 20

        headers = results.get(
            "headers",
            {}
        )

        score += min(
            headers.get(
                "score",
                0
            ) // 4,
            25
        )

    except Exception:
        pass

    return min(score, 100)


def display_results(
    domain,
    results,
    report_data,
    ui
):

    console.print()

    ui.show_scan_summary(
        domain,
        results
    )

    if "dns" in results:

        ui.dns_table(
            results["dns"]
        )

    if "ssl" in results:

        ui.show_ssl_info(
            results["ssl"]
        )

    if "tls" in results:

        ui.show_tls_info(
            results["tls"]
        )

    score = calculate_score(
        results
    )

    ui.security_score(
        score
    )

    ui.show_report_paths(
        report_data
    )


def main():

    ui = TerminalUI()

    ui.banner()

    domain = ui.ask_domain()

    if not domain:

        ui.show_error(
            "No domain entered."
        )

        return

    results = run_scan(
        domain,
        ui
    )

    report_data = ReportGenerator(
        domain,
        results
    ).generate()

    display_results(
        domain,
        results,
        report_data,
        ui
    )

    ui.success(
        "Scan Completed Successfully"
    )


if __name__ == "__main__":
    main()