#!/usr/bin/env python3

import ssl
import socket
import urllib.parse
import csv

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

def check_https(hostname):
    https_url = f"https://{hostname}/"
    try:
        st, loc = get_http_status(hostname)
        print(f"HTTP status: {st}")
        if loc:
            print(f"Redirecting to: {loc}")
        if st < 300:
            http_status = "Insecure content"
        elif 300 <= st < 400:
            if loc.lower().startswith(f"https://{hostname}/"):
                http_status = f"Redirects to self ({st})"
            elif loc.lower().startswith("https://"):
                http_status = f"Redirects to secure ({st}, {loc})"
                https_url = loc
            else:
                http_status = f"Redirects to insecure ({st}, {loc})"
        else:
            http_status = f"Broken ({st})"
    except requests.RequestException as e:
        http_status = f"Non-functional ({e})"
    print(f"Overall HTTP status: {http_status}")

    sth = None
    hsts = None
    issuer = None
    notAfter = None
    securitytxt = None
    try:
        print("Trying TLS connection…")
        parsed = urllib.parse.urlparse(https_url)
        issuer, notAfter = get_remote_tls_cert(parsed.hostname, parsed.port)
        print(f"TLS connection OK: issuer: {issuer}, notAfter: {notAfter}")
        sth, hsts = get_hsts_header(https_url)
        print(f"HTTPS Status {sth}, HSTS: {hsts}")
        https_status = f"OK ({sth})"
        securitytxt = get_security_txt(parsed.hostname, parsed.port)
    except (ssl.SSLError, socket.error, ConnectionRefusedError, ssl.CertificateError) as e:
        print(f"Broken TLS connection: {e}")
        https_status = f"Broken ({e})"

    return (http_status, https_status, hsts, securitytxt, issuer, notAfter,)


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
        writer.writerow(("Domain", "HTTP Status", "HTTPS Status", "HSTS Header", "GET /.well-known/security.txt", "issuer", "notAfter",))

    for line in domainlist:
        d = line.strip().rstrip(".")
        if d.startswith("#") or d == "":
            continue
        r = check_https(d)
        if r and report:
            writer.writerow([d, *r])


if __name__ == "__main__":
    main()
