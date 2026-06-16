import dns.resolver


class DNSScanner:

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
            "A": self._query("A"),
            "AAAA": self._query("AAAA"),
            "MX": self._query("MX"),
            "NS": self._query("NS"),
            "TXT": self._query("TXT")
        }

        # SPF Extraction
        spf_records = []

        for txt in results["TXT"]:
            if "v=spf1" in txt.lower():
                spf_records.append(txt)

        results["SPF"] = spf_records

        return results


if __name__ == "__main__":

    scanner = DNSScanner("google.com")

    from pprint import pprint
    pprint(scanner.scan())