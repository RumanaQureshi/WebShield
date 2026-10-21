
from flask import Flask, render_template, request, make_response
import requests
import csv
import io
from urllib.parse import urlparse

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


def scan_website(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid URL starting with https:// or http://.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")

    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost addresses are not supported.")

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "WebShield-Student-Scanner/1.0"}
        )
    except requests.RequestException:
        raise ValueError(
            "Could not reach the website. Check the URL and internet connection."
        )

    results = []

    for header, details in SECURITY_HEADERS.items():
        present = header in response.headers
        results.append({
            "name": header,
            "present": present,
            "description": details[0],
            "recommendation": details[1]
        })

    return {
        "url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "https": urlparse(response.url).scheme == "https",
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
    writer.writerow(["HTTPS", "Enabled" if report["https"] else "Not detected"])
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
    app.run(debug=True, port=5001)
