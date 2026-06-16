import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLScanner:

    def __init__(self, domain):
        self.domain = domain

    def scan(self):

        results = {
            "issuer": None,
            "subject": None,
            "serial_number": None,
            "version": None,
            "signature_algorithm": None,
            "not_before": None,
            "not_after": None,
            "san": [],
            "public_key_size": None,
            "tls_version": None,
            "cipher": None,
            "ssl_available": False,
            "error": None
        }

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (self.domain, 443),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=self.domain
                ) as ssock:

                    results["tls_version"] = ssock.version()

                    cipher = ssock.cipher()
                    if cipher:
                        results["cipher"] = {
                            "name": cipher[0],
                            "protocol": cipher[1],
                            "bits": cipher[2]
                        }

                    der_cert = ssock.getpeercert(binary_form=True)

            cert = x509.load_der_x509_certificate(
                der_cert,
                default_backend()
            )

            results["ssl_available"] = True

            results["serial_number"] = str(
                cert.serial_number
            )

            results["version"] = cert.version.name

            results["not_before"] = str(
                cert.not_valid_before_utc
            )

            results["not_after"] = str(
                cert.not_valid_after_utc
            )

            results["signature_algorithm"] = (
                cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm
                else "Unknown"
            )

            results["issuer"] = {
                attr.oid._name: attr.value
                for attr in cert.issuer
            }

            results["subject"] = {
                attr.oid._name: attr.value
                for attr in cert.subject
            }

            try:

                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )

                results["san"] = san.value.get_values_for_type(
                    x509.DNSName
                )

            except Exception:
                pass

            try:

                public_key = cert.public_key()

                if hasattr(public_key, "key_size"):
                    results["public_key_size"] = (
                        public_key.key_size
                    )

            except Exception:
                pass

        except Exception as e:

            results["error"] = str(e)

        return results


if __name__ == "__main__":

    from pprint import pprint

    scanner = SSLScanner("google.com")

    pprint(scanner.scan())