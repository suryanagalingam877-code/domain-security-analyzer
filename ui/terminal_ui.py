from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn
)
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from rich.text import Text


class TerminalUI:

    def __init__(self):

        self.console = Console()

    def banner(self):

        banner_text = """
██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
"""

        panel = Panel(
            Align.center(
                Text(
                    banner_text,
                    style="bold cyan"
                )
            ),
            title="[bold green]DOMAIN SECURITY ANALYZER[/bold green]",
            border_style="bright_cyan"
        )

        self.console.print(panel)

    def ask_domain(self):

        self.console.print()

        domain = self.console.input(
            "[bold yellow]Enter Domain:[/bold yellow] "
        )

        return domain.strip()

    def progress_bar(self):

        return Progress(

            SpinnerColumn(
                style="cyan"
            ),

            TextColumn(
                "[progress.description]{task.description}"
            ),

            BarColumn(
                complete_style="bright_cyan"
            ),

            TextColumn(
                "[progress.percentage]{task.percentage:>3.0f}%"
            ),

            TimeElapsedColumn()
        )

    def show_scan_summary(
        self,
        domain,
        results
    ):

        summary = Table(
            title=f"Scan Summary - {domain}",
            border_style="bright_cyan"
        )

        summary.add_column(
            "Module",
            style="cyan"
        )

        summary.add_column(
            "Status",
            style="green"
        )

        for module in results:

            summary.add_row(
                module.upper(),
                "✓ Completed"
            )

        self.console.print()
        self.console.print(summary)

    def dns_table(self, dns_results):

        table = Table(
            title="DNS Records",
            border_style="cyan"
        )

        table.add_column(
            "Type",
            style="bright_cyan"
        )

        table.add_column(
            "Value",
            style="white"
        )

        for record_type, values in dns_results.items():

            if not values:
                continue

            if isinstance(
                values,
                list
            ):

                value = "\n".join(
                    str(v)
                    for v in values
                )

            else:

                value = str(values)

            table.add_row(
                record_type,
                value
            )

        self.console.print(table)

    def security_score(
        self,
        score
    ):

        color = "red"

        if score >= 80:
            color = "green"

        elif score >= 60:
            color = "yellow"

        panel = Panel(
            Align.center(
                f"[bold {color}]"
                f"{score}/100"
                f"[/bold {color}]"
            ),
            title="Security Score",
            border_style=color
        )

        self.console.print(panel)

    def show_ssl_info(
        self,
        ssl_data
    ):

        table = Table(
            title="SSL Certificate",
            border_style="magenta"
        )

        table.add_column(
            "Field"
        )

        table.add_column(
            "Value"
        )

        for key, value in ssl_data.items():

            if value is None:
                continue

            table.add_row(
                str(key),
                str(value)
            )

        self.console.print(table)

    def show_tls_info(
        self,
        tls_data
    ):

        table = Table(
            title="TLS Support",
            border_style="green"
        )

        table.add_column(
            "Version"
        )

        table.add_column(
            "Supported"
        )

        for version, data in tls_data.items():

            if not isinstance(
                data,
                dict
            ):
                continue

            supported = (
                "✓"
                if data.get(
                    "supported"
                )
                else "✗"
            )

            table.add_row(
                version,
                supported
            )

        self.console.print(table)

    def show_report_paths(
        self,
        report_data
    ):

        panel = Panel(
            f"""
[bold green]JSON Report[/bold green]

{report_data.get('json_report')}

[bold cyan]HTML Report[/bold cyan]

{report_data.get('html_report')}
""",
            title="Generated Reports",
            border_style="bright_green"
        )

        self.console.print(panel)

    def show_error(
        self,
        message
    ):

        self.console.print(
            Panel(
                message,
                title="ERROR",
                border_style="red"
            )
        )

    def success(
        self,
        message
    ):

        self.console.print(
            Panel(
                message,
                border_style="green"
            )
        )


if __name__ == "__main__":

    ui = TerminalUI()

    ui.banner()

    domain = ui.ask_domain()

    ui.success(
        f"Target Selected: {domain}"
    )