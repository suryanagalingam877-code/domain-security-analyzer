from flask import Flask, render_template, request, jsonify
from datetime import datetime

from core.dns_scanner import DNSScanner
from core.ssl_scanner import SSLScanner
from core.tls_scanner import TLSScanner
from core.dmarc_scanner import DmarcScanner
from core.dkim_scanner import DKIMScanner
from core.dnssec_scanner import DNSSECScanner
from core.caa_scanner import CAAScanner
from core.headers_scanner import HeadersScanner
from core.whois_scanner import WhoisScanner
from core.subdomain_scanner import SubdomainScanner
from core.report_generator import ReportGenerator

app = Flask(__name__)


def run_scan(domain):

    results = {}

    try:
        results["dns"] = DNSScanner(domain).scan()
    except Exception as e:
        results["dns"] = {"error": str(e)}

    try:
        results["dmarc"] = DmarcScanner(domain).scan()
    except Exception as e:
        results["dmarc"] = {"error": str(e)}

    try:
        results["dkim"] = DKIMScanner(domain).scan()
    except Exception as e:
        results["dkim"] = {"error": str(e)}

    try:
        results["dnssec"] = DNSSECScanner(domain).scan()
    except Exception as e:
        results["dnssec"] = {"error": str(e)}

    try:
        results["caa"] = CAAScanner(domain).scan()
    except Exception as e:
        results["caa"] = {"error": str(e)}

    try:
        results["ssl"] = SSLScanner(domain).scan()
    except Exception as e:
        results["ssl"] = {"error": str(e)}

    try:
        results["tls"] = TLSScanner(domain).scan()
    except Exception as e:
        results["tls"] = {"error": str(e)}

    try:
        results["headers"] = HeadersScanner(domain).scan()
    except Exception as e:
        results["headers"] = {"error": str(e)}

    try:
        results["whois"] = WhoisScanner(domain).scan()
    except Exception as e:
        results["whois"] = {"error": str(e)}

    try:
        results["subdomains"] = SubdomainScanner(domain).scan()
    except Exception as e:
        results["subdomains"] = {"error": str(e)}

    report = ReportGenerator(
        domain,
        results
    ).generate()

    results["reports"] = report

    return results


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()

    domain = data.get(
        "domain",
        ""
    ).strip()

    if not domain:
        return jsonify({
            "success": False,
            "error": "Domain is required"
        })

    try:

        results = run_scan(domain)

        return jsonify({
            "success": True,
            "domain": domain,
            "timestamp": str(datetime.now()),
            "results": results
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        })


@app.route("/health")
def health():

    return jsonify({
        "status": "online"
    })


if __name__ == "__main__":

    import threading
    import webbrowser
    import time

    HOST = "127.0.0.1"
    PORT = 5000

    def open_browser():

        time.sleep(2)

        webbrowser.open(
            f"http://{HOST}:{PORT}"
        )

    threading.Thread(
        target=open_browser,
        daemon=True
    ).start()

    app.run(
        host=HOST,
        port=PORT,
        debug=False
    )