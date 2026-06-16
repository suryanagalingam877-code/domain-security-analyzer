const domainInput =
document.getElementById("domain");

const scanButton =
document.getElementById("scanBtn");

const loading =
document.getElementById("loading");

const results =
document.getElementById("results");


async function startScan() {

    const domain =
    domainInput.value.trim();

    if (!domain) {

        alert(
            "Please enter a domain"
        );

        return;
    }

    loading.classList.remove(
        "hidden"
    );

    results.classList.add(
        "hidden"
    );

    scanButton.disabled = true;

    try {

        const response =
        await fetch(
            "/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                    "application/json"
                },

                body: JSON.stringify({
                    domain
                })
            }
        );

        const data =
        await response.json();

        loading.classList.add(
            "hidden"
        );

        scanButton.disabled = false;

        if (!data.success) {

            alert(
                data.error
            );

            return;
        }

        renderResults(
            data.results
        );

    } catch (err) {

        loading.classList.add(
            "hidden"
        );

        scanButton.disabled = false;

        alert(
            "Scan failed\n\n" +
            err
        );
    }
}


function renderResults(data) {

    results.classList.remove(
        "hidden"
    );

    setContent(
        "dns",
        data.dns
    );

    setContent(
        "dmarc",
        data.dmarc
    );

    setContent(
        "dkim",
        data.dkim
    );

    setContent(
        "dnssec",
        data.dnssec
    );

    setContent(
        "caa",
        data.caa
    );

    setContent(
        "ssl",
        data.ssl
    );

    setContent(
        "tls",
        data.tls
    );

    setContent(
        "headers",
        data.headers
    );

    setContent(
        "whois",
        data.whois
    );

    setContent(
        "subdomains",
        data.subdomains
    );

    const reportBox =
    document.getElementById(
        "reportLinks"
    );

    if (
        data.reports
    ) {

        reportBox.innerHTML =
        `
        <p>
            JSON Report:
            <br>
            ${data.reports.json_report}
        </p>

        <br>

        <p>
            HTML Report:
            <br>
            ${data.reports.html_report}
        </p>
        `;
    }
}


function setContent(
    id,
    value
) {

    const element =
    document.getElementById(
        id
    );

    if (!element)
        return;

    element.textContent =
    JSON.stringify(
        value,
        null,
        2
    );
}


domainInput.addEventListener(
    "keydown",
    function(event) {

        if (
            event.key === "Enter"
        ) {

            startScan();
        }
    }
);