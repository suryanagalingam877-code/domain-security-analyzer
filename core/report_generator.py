import os
import json
from datetime import datetime


class ReportGenerator:

    def __init__(self, domain, results):
        self.domain = domain
        self.results = results

    def generate(self):
        return {
            "json_report": self.generate_json(),
            "html_report": self.generate_html()
        }

    def generate_json(self):

        os.makedirs(
            "reports/json",
            exist_ok=True
        )

        filename = (
            f"reports/json/"
            f"{self.domain}.json"
        )

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                self.results,
                f,
                indent=4,
                default=str
            )

        return filename

    def generate_html(self):

        os.makedirs(
            "reports/html",
            exist_ok=True
        )

        filename = (
            f"reports/html/"
            f"{self.domain}.html"
        )

        html = f"""
<html>
<head>
<title>{self.domain}</title>
</head>

<body>

<h1>Domain Report</h1>

<pre>
{json.dumps(self.results, indent=4, default=str)}
</pre>

</body>
</html>
"""

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(html)

        return filename