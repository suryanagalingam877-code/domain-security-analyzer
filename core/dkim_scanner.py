import dns.resolver


class DKIMScanner:

    def __init__(self, domain):

        self.domain = domain

        self.common_selectors = [
            "default",
            "selector1",
            "selector2",
            "google",
            "googlemail",
            "k1",
            "k2",
            "dkim",
            "mail",
            "smtp",
            "mandrill",
            "amazonses",
            "zendesk",
            "zoho",
            "protonmail",
            "s1",
            "s2"
        ]

    def _query_selector(self, selector):

        try:

            record_name = (
                f"{selector}._domainkey."
                f"{self.domain}"
            )

            answers = dns.resolver.resolve(
                record_name,
                "TXT"
            )

            records = []

            for answer in answers:

                try:

                    if hasattr(answer, "strings"):

                        txt = "".join(
                            part.decode()
                            for part in answer.strings
                        )

                    else:

                        txt = str(answer)

                except Exception:

                    txt = str(answer)

                records.append(txt)

            return {
                "selector": selector,
                "record_name": record_name,
                "found": True,
                "records": records
            }

        except Exception:

            return None

    def _analyze_record(self, record):

        result = {
            "version": None,
            "key_type": None,
            "public_key_present": False
        }

        parts = record.split(";")

        for part in parts:

            part = part.strip()

            if "=" not in part:
                continue

            key, value = part.split(
                "=",
                1
            )

            key = key.strip().lower()
            value = value.strip()

            if key == "v":
                result["version"] = value

            elif key == "k":
                result["key_type"] = value

            elif key == "p":

                if value:
                    result[
                        "public_key_present"
                    ] = True

        return result

    def scan(self):

        results = {
            "domain": self.domain,
            "dkim_enabled": False,
            "selectors_found": [],
            "total_selectors_found": 0,
            "score": 0,
            "status": "Not Configured",
            "error": None
        }

        try:

            found = []

            for selector in (
                self.common_selectors
            ):

                result = self._query_selector(
                    selector
                )

                if result:

                    analysis = []

                    for record in result[
                        "records"
                    ]:

                        analysis.append(
                            self._analyze_record(
                                record
                            )
                        )

                    result[
                        "analysis"
                    ] = analysis

                    found.append(result)

            results[
                "selectors_found"
            ] = found

            results[
                "total_selectors_found"
            ] = len(found)

            if found:

                results[
                    "dkim_enabled"
                ] = True

                results[
                    "status"
                ] = "Configured"

                score = 50

                for selector in found:

                    for item in selector[
                        "analysis"
                    ]:

                        if item[
                            "public_key_present"
                        ]:
                            score += 5

                        if (
                            item[
                                "key_type"
                            ]
                            == "rsa"
                        ):
                            score += 2

                if score > 100:
                    score = 100

                results[
                    "score"
                ] = score

            else:

                results[
                    "status"
                ] = "Not Configured"

                results[
                    "score"
                ] = 0

        except Exception as e:

            results[
                "error"
            ] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = DKIMScanner(
        "google.com"
    )

    pprint(
        scanner.scan()
    )