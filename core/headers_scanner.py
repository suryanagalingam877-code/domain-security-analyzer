import requests


class HeadersScanner:

    def __init__(self, domain):
        self.domain = domain

    def scan(self):

        results = {
            "url": f"https://{self.domain}",
            "reachable": False,
            "status_code": None,
            "headers": {},
            "security_headers": {},
            "missing_headers": [],
            "score": 0,
            "grade": "F",
            "server": None,
            "powered_by": None,
            "error": None
        }

        security_headers = {
            "Strict-Transport-Security": False,
            "Content-Security-Policy": False,
            "X-Frame-Options": False,
            "X-Content-Type-Options": False,
            "Referrer-Policy": False,
            "Permissions-Policy": False,
            "Cross-Origin-Opener-Policy": False,
            "Cross-Origin-Embedder-Policy": False
        }

        try:

            response = requests.get(
                f"https://{self.domain}",
                timeout=15,
                allow_redirects=True,
                headers={
                    "User-Agent":
                    "DomainSecurityAnalyzer/1.0"
                }
            )

            results["reachable"] = True
            results["status_code"] = response.status_code

            headers = dict(response.headers)

            results["headers"] = headers

            results["server"] = headers.get(
                "Server",
                "Not Disclosed"
            )

            results["powered_by"] = headers.get(
                "X-Powered-By",
                "Not Disclosed"
            )

            score = 0

            for header in security_headers:

                if header in headers:

                    security_headers[header] = True
                    score += 12.5

            results["security_headers"] = security_headers

            results["missing_headers"] = [

                header
                for header, present
                in security_headers.items()
                if not present

            ]

            results["score"] = round(score)

            if score >= 90:
                grade = "A+"
            elif score >= 80:
                grade = "A"
            elif score >= 70:
                grade = "B"
            elif score >= 60:
                grade = "C"
            elif score >= 50:
                grade = "D"
            else:
                grade = "F"

            results["grade"] = grade

        except Exception as e:

            results["error"] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = HeadersScanner(
        "google.com"
    )

    pprint(scanner.scan())