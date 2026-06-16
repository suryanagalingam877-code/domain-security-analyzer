import socket
import requests
import concurrent.futures


class SubdomainScanner:

    def __init__(self, domain):
        self.domain = domain

    def _resolve(self, hostname):

        try:

            ip = socket.gethostbyname(hostname)

            return {
                "subdomain": hostname,
                "ip": ip,
                "alive": True
            }

        except Exception:
            return None

    def _fetch_crtsh(self):

        url = (
            f"https://crt.sh/"
            f"?q=%.{self.domain}&output=json"
        )

        try:

            response = requests.get(
                url,
                timeout=30,
                headers={
                    "User-Agent":
                    "DomainSecurityAnalyzer"
                }
            )

            if response.status_code != 200:
                return []

            data = response.json()

            subdomains = set()

            for entry in data:

                if "name_value" not in entry:
                    continue

                names = entry["name_value"].split("\n")

                for name in names:

                    name = name.strip().lower()

                    if "*" in name:
                        continue

                    if name.endswith(self.domain):
                        subdomains.add(name)

            return sorted(subdomains)

        except Exception:
            return []

    def scan(self):

        discovered = self._fetch_crtsh()

        validated = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=50
        ) as executor:

            futures = [
                executor.submit(
                    self._resolve,
                    sub
                )
                for sub in discovered
            ]

            for future in concurrent.futures.as_completed(
                futures
            ):

                result = future.result()

                if result:
                    validated.append(result)

        validated = sorted(
            validated,
            key=lambda x: x["subdomain"]
        )

        return {
            "count": len(validated),
            "subdomains": validated
        }


if __name__ == "__main__":

    from pprint import pprint

    scanner = SubdomainScanner(
        "google.com"
    )

    pprint(scanner.scan())