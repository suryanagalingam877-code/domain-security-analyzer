import dns.resolver


class CAAScanner:

    def __init__(self, domain):
        self.domain = domain

    def scan(self):

        results = {
            "domain": self.domain,
            "caa_enabled": False,
            "records": [],
            "authorized_cas": [],
            "wildcard_cas": [],
            "iodef": [],
            "score": 0,
            "status": "Not Configured",
            "error": None
        }

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "CAA"
            )

            authorized_cas = []
            wildcard_cas = []
            iodef = []

            for answer in answers:

                record = str(answer)

                results["records"].append(
                    record
                )

                try:

                    flags = answer.flags
                    tag = answer.tag.decode()
                    value = (
                        answer.value.decode()
                    )

                except Exception:

                    parts = record.split()

                    if len(parts) >= 3:

                        flags = parts[0]
                        tag = parts[1]
                        value = " ".join(
                            parts[2:]
                        )

                    else:
                        continue

                tag = tag.lower()

                if tag == "issue":

                    authorized_cas.append(
                        value
                    )

                elif tag == "issuewild":

                    wildcard_cas.append(
                        value
                    )

                elif tag == "iodef":

                    iodef.append(
                        value
                    )

            results["authorized_cas"] = (
                authorized_cas
            )

            results["wildcard_cas"] = (
                wildcard_cas
            )

            results["iodef"] = iodef

            if (
                authorized_cas
                or wildcard_cas
            ):

                results["caa_enabled"] = True

                results["status"] = (
                    "Configured"
                )

                score = 50

                if authorized_cas:
                    score += 25

                if wildcard_cas:
                    score += 15

                if iodef:
                    score += 10

                results["score"] = score

            else:

                results["status"] = (
                    "CAA Present But Empty"
                )

        except dns.resolver.NoAnswer:

            results["status"] = (
                "No CAA Records"
            )

        except dns.resolver.NXDOMAIN:

            results["error"] = (
                "Domain Not Found"
            )

        except Exception as e:

            results["error"] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = CAAScanner(
        "google.com"
    )

    pprint(scanner.scan())