#!/usr/bin/env python3

import ssl
import socket
import csv

import requests
import click


def get_remote_tls_cert(hostname, port=443, timeout=1):
    """
    Connect to a hostname. Return parsed peer certificate as dict.
    Raise ssl.SSLError on TLS error
    Raise ssl.certificateerror on unmatching certificate
    Raise socket.gaierror on DNS error
    Raise ConnectionRefusedError on connection refused
    Raise socket.timeout on timeout
    """
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


def get_hsts_header(hostname, timeout=5):
    """
    Issue HTTP HEAD request for the root of the domain name.
    Return tuple with status code and Location output (if any).
    """
    print(f"Checking https://{hostname}/ HSTS header…")
    r = requests.head(f"https://{hostname}/", timeout=timeout)
    return (r.status_code, r.headers.get("Strict-Transport-Security"))


def check_https(hostname):
    try:
        st, loc = get_http_status(hostname)
    except requests.RequestException as e:
        return
    print(f"HTTP status: {st}")
    if loc:
        print(f"Redirecting to: {loc}")
    redirects_to_https = False
    redirects_to_self = False
    if st // 100 == 3 and loc.lower().startswith("https://"):
        redirects_to_https = True
        if loc.lower().startswith(f"https://{hostname}/"):
            redirects_to_self = True

    sth = None
    hsts = None
    issuer = None
    notAfter = None
    try:
        print("Trying TLS connection…")
        issuer, notAfter = get_remote_tls_cert(hostname)
        print(f"TLS connection OK: issuer: {issuer}, notAfter: {notAfter}")
        sth, hsts = get_hsts_header(hostname)
        print(f"HTTPS Status {sth}, HSTS: {hsts}")
    except (ssl.SSLError, socket.error, ConnectionRefusedError, ssl.CertificateError) as e:
        print(f"Broken TLS connection: {e}")

    return (st, loc, redirects_to_https, redirects_to_self, sth, hsts, issuer, notAfter,)


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
        writer.writerow(("Domain", "HTTP Status", "Redirects to", "Redirects to HTTPS", "Redirects to self", "HTTPS Status", "HSTS Header", "issuer", "notAfter",))

    for line in domainlist:
        d = line.strip().rstrip(".")
        if d.startswith("#") or d == "":
            continue
        r = check_https(d)
        if r and report:
            writer.writerow([d, *r])


if __name__ == "__main__":
    main()
