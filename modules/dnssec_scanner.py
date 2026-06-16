import dns.resolver


class DNSSECScanner:

    def __init__(self, domain):
        self.domain = domain

    def _query(self, record_type):

        try:

            answers = dns.resolver.resolve(
                self.domain,
                record_type
            )

            return [str(r) for r in answers]

        except Exception:

            return []

    def scan(self):

        results = {
            "domain": self.domain,
            "dnssec_enabled": False,
            "dnskey_records": [],
            "ds_records": [],
            "rrsig_records": [],
            "score": 0,
            "status": "Not Enabled",
            "error": None
        }

        try:

            dnskey_records = self._query(
                "DNSKEY"
            )

            ds_records = self._query(
                "DS"
            )

            rrsig_records = self._query(
                "RRSIG"
            )

            results["dnskey_records"] = (
                dnskey_records
            )

            results["ds_records"] = (
                ds_records
            )

            results["rrsig_records"] = (
                rrsig_records
            )

            dnskey_found = (
                len(dnskey_records) > 0
            )

            ds_found = (
                len(ds_records) > 0
            )

            rrsig_found = (
                len(rrsig_records) > 0
            )

            if dnskey_found:
                results["score"] += 40

            if ds_found:
                results["score"] += 30

            if rrsig_found:
                results["score"] += 30

            if (
                dnskey_found
                and ds_found
                and rrsig_found
            ):

                results["dnssec_enabled"] = True

                results["status"] = (
                    "Fully Configured"
                )

            elif dnskey_found or ds_found:

                results["status"] = (
                    "Partially Configured"
                )

            else:

                results["status"] = (
                    "Not Enabled"
                )

        except Exception as e:

            results["error"] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = DNSSECScanner(
        "cloudflare.com"
    )

    pprint(scanner.scan())