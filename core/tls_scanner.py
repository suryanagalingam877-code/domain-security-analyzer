import socket
import ssl


class TLSScanner:

    def __init__(self, domain):
        self.domain = domain

    def _test_version(self, tls_version):

        try:

            context = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            context.minimum_version = tls_version
            context.maximum_version = tls_version

            with socket.create_connection(
                (self.domain, 443),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=self.domain
                ) as ssock:

                    return {
                        "supported": True,
                        "negotiated_version": ssock.version(),
                        "cipher": ssock.cipher()[0]
                        if ssock.cipher()
                        else None
                    }

        except Exception:

            return {
                "supported": False,
                "negotiated_version": None,
                "cipher": None
            }

    def scan(self):

        results = {}

        versions = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3
        }

        for version_name, version_obj in versions.items():

            results[version_name] = self._test_version(
                version_obj
            )

        supported_versions = []

        for name, data in results.items():

            if data["supported"]:
                supported_versions.append(name)

        results["supported_versions"] = supported_versions

        if supported_versions:
            results["highest_supported"] = supported_versions[-1]
        else:
            results["highest_supported"] = None

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = TLSScanner("google.com")

    pprint(scanner.scan())