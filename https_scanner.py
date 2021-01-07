#!/usr/bin/env python3

import ssl
import socket
import urllib.parse
import csv
import time

import requests
import click


def get_remote_tls_cert(hostname, port=None, timeout=1):
    """
    Connect to a hostname. Return parsed peer certificate as dict.
    Raise ssl.SSLError on TLS error
    Raise ssl.certificateerror on unmatching certificate
    Raise socket.gaierror on DNS error
    Raise ConnectionRefusedError on connection refused
    Raise socket.timeout on timeout
    """
    port = port or 443
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
            c = sslsock.getpeercert()
            issuer = [tag[0][1] for tag in c["issuer"]
                      if tag[0][0] == "commonName"][0]
            notAfter = c["notAfter"]
            return (issuer, notAfter)


def get_http_status(hostname, timeout=1):
    """
    Issue HTTP HEAD request for the root of the domain name.
    Return tuple with status code and Location output (if any).
    """
    print(f"Checking http://{hostname}/…")
    r = requests.head(f"http://{hostname}/", timeout=timeout)
    return (r.status_code, r.headers.get("Location"))


def get_hsts_header(url, timeout=5):
    """
    Issue HTTP HEAD request for the root of the domain name.
    Return tuple with status code and Location output (if any).
    """
    print(f"Checking HSTS header…")
    r = requests.head(url, timeout=timeout)
    return (r.status_code, r.headers.get("Strict-Transport-Security"))

def get_security_txt(hostname, port=None, timeout=5):
    port = f":{port}" if port else ""
    r = requests.head(f"https://{hostname}{port}/.well-known/security.txt",
                      timeout=timeout)
    return r.status_code


def get_grade(minus_points, plus_points):
    grade = min(5, minus_points)
    return chr(ord("A") + grade) + "+" * plus_points


def get_ssllabs_grade(hostname, force_check=False):
    ssllabs_api = "https://api.ssllabs.com/api/v3/"
    reqn = 0
    try:
        while True:
            reqn += 1
            r = requests.get(ssllabs_api + "analyze", params={
                                "host": hostname,
                                "maxAge": 99999,
                             }).json()
            status = r.get("status")
            eps = r.get("endpoints", [])
            print(f"SSL Labs status {status}")
            if status == "DNS":
                print("Sleeping 10 seconds to allow DNS resolution")
                time.sleep(10)
            elif status == "IN_PROGRESS" and force_check and reqn < 8:
                for ep in eps:
                    print(f"endpoint {ep.get('ipAddress')} progress {ep.get('progress')}")
                print("Sleeping 60 seconds to allow SSL Labs analysis")
                time.sleep(60)
            elif status == "ERROR":
                return
            else:
                if not status == "READY":
                    print("Giving up SSL Labs")
                grades = [e["grade"] for e in eps if e.get("grade")]
                return max(grades) if grades else None
    except requests.exceptions.RequestException:
        return


def check_https(hostname):
    https_url = f"https://{hostname}/"
    minus_points = 0
    plus_points = 0
    try:
        st, loc = get_http_status(hostname)
        print(f"HTTP status: {st}")
        if loc:
            print(f"Redirecting to: {loc}")
        if st < 300:
            http_status = "Insecure content"
            minus_points += 2
        elif 300 <= st < 400:
            if loc.lower().startswith(f"https://{hostname}/"):
                http_status = f"Redirects to self ({st})"
            elif loc.lower().startswith("https://"):
                http_status = f"Redirects to secure ({st}, {loc})"
                https_url = loc
            else:
                http_status = f"Redirects to insecure ({st}, {loc})"
                minus_points += 2
        else:
            http_status = f"Broken ({st})"
            minus_points += 1
    except requests.RequestException as e:
        http_status = f"Non-functional ({e})"
        minus_points += 1
    print(f"Overall HTTP status: {http_status}")

    sth = None
    hsts = None
    issuer = None
    notAfter = None
    securitytxt = None
    do_ssl_labs = False
    try:
        print("Trying TLS connection…")
        parsed = urllib.parse.urlparse(https_url)
        issuer, notAfter = get_remote_tls_cert(parsed.hostname, parsed.port)
        print(f"TLS connection OK: issuer: {issuer}, notAfter: {notAfter}")
        sth, hsts = get_hsts_header(https_url)
        print(f"HTTPS Status {sth}, HSTS: {hsts}")
        if hsts is not None and "max-age=" in hsts:
            plus_points += 1
        https_status = f"OK ({sth})"
        securitytxt = get_security_txt(parsed.hostname, parsed.port)
        if securitytxt == 200:
            plus_points += 1
        if "TERENA SSL High Assurance CA" in issuer:
            plus_points += 1
        if not issuer.startswith("TERENA"):
            minus_points +=1

    except (socket.error, ConnectionRefusedError) as e:
        print(f"Broken TLS connection: {e}")
        https_status = f"Broken ({e})"
        minus_points += 3
        if http_status.startswith("Non-functional"):
            return
    except (ssl.SSLError, ssl.CertificateError) as e:
        print(f"Broken TLS connection: {e}")
        https_status = f"Broken ({e})"
        minus_points += 3
        do_ssl_labs = True

    grade = get_grade(minus_points, plus_points)
    ssllabs_url = "https://www.ssllabs.com/ssltest/analyze.html?d=" + hostname
    ssllabs_grade = get_ssllabs_grade(hostname, do_ssl_labs)


    return (grade, http_status, https_status, hsts, securitytxt, issuer, ssllabs_grade, ssllabs_url)


@click.command()
@click.argument("domainlist", type=click.File('r'))
@click.option("--report", type=click.File('w'))
def main(domainlist, report):
    """
    Scan HTTPS status for given domain list.
    Return Optional CSV report.
    """
    if report:
        writer = csv.writer(report)
        writer.writerow(("Domain", "Grade", "HTTP Status", "HTTPS Status", "HSTS Header", "GET /.well-known/security.txt", "issuer", "SSL Labs grade", "SSL Labs URL",))

    for line in domainlist:
        d = line.strip().rstrip(".")
        if d.startswith("#") or d == "":
            continue
        r = check_https(d)
        if r and report:
            writer.writerow([d, *r])


if __name__ == "__main__":
    main()
