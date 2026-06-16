import whois
from datetime import datetime


class WhoisScanner:

    def __init__(self, domain):
        self.domain = domain

    def _normalize_date(self, value):

        if not value:
            return None

        if isinstance(value, list):
            value = value[0]

        if isinstance(value, datetime):
            return value.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        return str(value)

    def _normalize_list(self, value):

        if not value:
            return []

        if isinstance(value, list):
            return [
                str(item)
                for item in value
            ]

        return [str(value)]

    def scan(self):

        results = {
            "domain": self.domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "emails": [],
            "organization": None,
            "country": None,
            "dnssec": None,
            "raw": {},
            "error": None
        }

        try:

            data = whois.whois(
                self.domain
            )

            results["registrar"] = (
                data.registrar
            )

            results["creation_date"] = (
                self._normalize_date(
                    data.creation_date
                )
            )

            results["expiration_date"] = (
                self._normalize_date(
                    data.expiration_date
                )
            )

            results["updated_date"] = (
                self._normalize_date(
                    data.updated_date
                )
            )

            results["name_servers"] = (
                self._normalize_list(
                    data.name_servers
                )
            )

            results["status"] = (
                self._normalize_list(
                    data.status
                )
            )

            results["emails"] = (
                self._normalize_list(
                    data.emails
                )
            )

            if hasattr(data, "org"):
                results["organization"] = (
                    data.org
                )

            if hasattr(data, "country"):
                results["country"] = (
                    data.country
                )

            if hasattr(data, "dnssec"):
                results["dnssec"] = (
                    data.dnssec
                )

            results["raw"] = {
                k: str(v)
                for k, v in data.items()
            }

        except Exception as e:

            results["error"] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = WhoisScanner(
        "google.com"
    )

    pprint(scanner.scan())