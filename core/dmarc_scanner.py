import dns.resolver
import re


class DmarcScanner:

    def __init__(self, domain):
        self.domain = domain

    def _parse_dmarc(self, record):

        parsed = {
            "version": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "rua": [],
            "ruf": [],
            "fo": None,
            "adkim": None,
            "aspf": None
        }

        parts = record.split(";")

        for part in parts:

            part = part.strip()

            if "=" not in part:
                continue

            key, value = part.split("=", 1)

            key = key.strip().lower()
            value = value.strip()

            if key == "v":
                parsed["version"] = value

            elif key == "p":
                parsed["policy"] = value

            elif key == "sp":
                parsed["subdomain_policy"] = value

            elif key == "pct":
                parsed["pct"] = value

            elif key == "rua":
                parsed["rua"] = [
                    x.strip()
                    for x in value.split(",")
                ]

            elif key == "ruf":
                parsed["ruf"] = [
                    x.strip()
                    for x in value.split(",")
                ]

            elif key == "fo":
                parsed["fo"] = value

            elif key == "adkim":
                parsed["adkim"] = value

            elif key == "aspf":
                parsed["aspf"] = value

        return parsed

    def _calculate_score(self, policy):

        if not policy:
            return 0

        policy = policy.lower()

        if policy == "reject":
            return 100

        if policy == "quarantine":
            return 80

        if policy == "none":
            return 40

        return 0

    def _enforcement_level(self, policy):

        if not policy:
            return "Not Configured"

        policy = policy.lower()

        if policy == "reject":
            return "Strong Enforcement"

        if policy == "quarantine":
            return "Medium Enforcement"

        if policy == "none":
            return "Monitoring Only"

        return "Unknown"

    def scan(self):

        results = {
            "domain": self.domain,
            "record_found": False,
            "raw_record": None,
            "valid": False,
            "score": 0,
            "enforcement": None,
            "parsed": {},
            "error": None
        }

        try:

            dmarc_domain = (
                f"_dmarc.{self.domain}"
            )

            answers = dns.resolver.resolve(
                dmarc_domain,
                "TXT"
            )

            dmarc_record = None

            for answer in answers:

                txt = "".join(
                    answer.strings[i].decode()
                    for i in range(
                        len(answer.strings)
                    )
                )

                if txt.lower().startswith(
                    "v=dmarc1"
                ):
                    dmarc_record = txt
                    break

            if not dmarc_record:

                results["error"] = (
                    "DMARC record not found"
                )

                return results

            results["record_found"] = True
            results["raw_record"] = dmarc_record

            parsed = self._parse_dmarc(
                dmarc_record
            )

            results["parsed"] = parsed

            version = parsed.get(
                "version"
            )

            policy = parsed.get(
                "policy"
            )

            if (
                version
                and version.upper()
                == "DMARC1"
            ):

                results["valid"] = True

            score = self._calculate_score(
                policy
            )

            results["score"] = score

            results["enforcement"] = (
                self._enforcement_level(
                    policy
                )
            )

        except dns.resolver.NXDOMAIN:

            results["error"] = (
                "Domain does not exist"
            )

        except dns.resolver.NoAnswer:

            results["error"] = (
                "No DMARC record found"
            )

        except Exception as e:

            results["error"] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = DmarcScanner(
        "google.com"
    )

    pprint(scanner.scan())