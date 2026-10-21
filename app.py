
import csv
import io
import ipaddress
import socket
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, render_template, request, make_response

app = Flask(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Helps protect against cross-site scripting.",
        "Configure a suitable Content-Security-Policy."
    ),
    "Strict-Transport-Security": (
        "Tells browsers to use HTTPS.",
        "Enable HSTS when your website fully supports HTTPS."
    ),
    "X-Content-Type-Options": (
        "Helps prevent MIME-type sniffing.",
        "Set X-Content-Type-Options to nosniff."
    ),
    "X-Frame-Options": (
        "Helps protect against clickjacking.",
        "Configure appropriate frame protection."
    ),
    "Referrer-Policy": (
        "Controls referrer information sent by browsers.",
        "Configure an appropriate Referrer-Policy."
    )
}


def validate_public_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid URL starting with https:// or http://.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")

    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid port.")

    host = parsed.hostname.lower()

    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost addresses are not supported.")

    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Could not resolve this website address.")

    if not addresses:
        raise ValueError("No IP address was found for this website.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError(
                "This website resolves to a non-public IP address and is blocked."
            )

    return url


def scan_website(url):
    validate_public_url(url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "WebShield-Student-Scanner/1.0"},
            stream=True
        )

        if 300 <= response.status_code < 400:
            response.close()
            location = response.headers.get("Location")
            if location:
                next_url = urljoin(url, location)
                validate_public_url(next_url)
                response = requests.get(
                    next_url,
                    timeout=10,
                    allow_redirects=False,
                    headers={"User-Agent": "WebShield-Student-Scanner/1.0"},
                    stream=True
                )

        response_headers = dict(response.headers)
        status_code = response.status_code
        final_url = response.url
        response.close()

    except requests.RequestException:
        raise ValueError(
            "Could not reach the website. Check the URL and internet connection."
        )

    results = []

    for header, details in SECURITY_HEADERS.items():
        present = header in response_headers
        results.append({
            "name": header,
            "present": present,
            "description": details[0],
            "recommendation": details[1]
        })

    return {
        "url": url,
        "final_url": final_url,
        "status_code": status_code,
        "https": urlparse(final_url).scheme == "https",
        "results": results,
        "passed": sum(item["present"] for item in results),
        "total": len(results)
    }


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            error = "Please enter a website URL."
        else:
            try:
                report = scan_website(url)
            except ValueError as exc:
                error = str(exc)

    return render_template("index.html", report=report, error=error)


@app.route("/download-report", methods=["POST"])
def download_report():
    url = request.form.get("url", "").strip()

    if not url:
        return "Please enter a website URL.", 400

    try:
        report = scan_website(url)
    except ValueError as exc:
        return str(exc), 400

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["WebShield Security Report"])
    writer.writerow(["Website", report["url"]])
    writer.writerow(["Final URL", report["final_url"]])
    writer.writerow(["HTTP Status", report["status_code"]])
    writer.writerow([
        "HTTPS", "Enabled" if report["https"] else "Not detected"
    ])
    writer.writerow([])
    writer.writerow([
        "Security Header", "Status", "Description", "Recommendation"
    ])

    for item in report["results"]:
        writer.writerow([
            item["name"],
            "PRESENT" if item["present"] else "MISSING",
            item["description"],
            "" if item["present"] else item["recommendation"]
        ])

    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=webshield-report.csv"
    )
    return response


if __name__ == "__main__":
    app.run(debug=False, port=5001)
