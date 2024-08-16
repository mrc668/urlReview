#!  /usr/bin/python3
import sys

from dotenv import load_dotenv
import os
#import dnspython as dns
#import dns.resolver
import socket
#import whois

import requests
import pprint
import urllib.parse

import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import asn1crypto
from asn1crypto import x509
from datetime import datetime

import datetime


def dissect_certificate(host, port):
    """
    Dissects a certificate from the given host and port, handling potential SSL errors.

    Args:
        host (str): The hostname of the server.
        port (int): The port number of the server.

    Returns:
        tuple: A tuple containing the subject (None if error occurs),
               notBefore (None if error occurs), and notAfter (None if error occurs).
    """

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)

        cert = asn1crypto.x509.Certificate.load(cert_der)

        subject = cert['tbs_certificate']['subject'].human_friendly
        not_before = cert['tbs_certificate']['validity']['not_before'].native
        not_after = cert['tbs_certificate']['validity']['not_after'].native

        # Access logDir from .env file
        logDir = os.getenv("logDir")
        full_path = os.path.join(logDir, "cert" )

        # Create the directory structure if it doesn't exist
        os.makedirs(full_path, exist_ok=True)

        # use openssl to examine the certificate
        # openssl x509 -in log/cert/example.com.pem -text | less
        try:
            with open(os.path.join(full_path, f"{host}.pem"), "wb") as f:
                f.write(cert_der)
        except OSError:
                print(f"Error saving certificate to {host}.pem")


        return subject, not_before, not_after
    except ssl.SSLError as e:
        print(f"Error connecting or verifying certificate: {e}")
        return None, None, None


'''
# Example usage:
host = 'example.com'
port = 443
subject, not_before, not_after = dissect_certificate(host, port)
'''

def getssl(host: str, port: int):
    """Retrieves and analyzes the SSL certificate from the specified host and port.

    Handles cases where the remote site is unavailable.
    """

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:  # Set a timeout
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                save_certificate_to_file(cert, host)
                analyze_certificate(cert, host)

    except (ssl.CertificateError, ssl.SSLError) as e:
        print(f"SSL error: {e}")
    except ConnectionError as e:
        print(f"Connection error: Remote site is unavailable: {e}. Cannot retreive SSL Certificate.")
    except socket.timeout:
        print("Timeout error: Remote site is not responding. Cannot retreive SSL Certificate.")

def save_certificate_to_file(cert_data: bytes, host: str):
  # Access logDir from .env file
  logDir = os.getenv("logDir")
  full_path = os.path.join(logDir, "cert" )

  # Create the directory structure if it doesn't exist
  os.makedirs(full_path, exist_ok=True)

  try:
      with open(os.path.join(full_path, f"{host}.pem"), "wb") as cert_file:
          cert_file.write("-----BEGIN CERTIFICATE-----\n".encode())
          cert_file.write(cert_data)
          cert_file.write("-----END CERTIFICATE-----\n".encode())
      print(f"Certificate saved to {host}.pem")
  except OSError:
        print(f"Error saving certificate to {host}.pem")

def analyze_certificate(cert_data: bytes, host: str):
    print("-" * 40)
    print(f"Analyzing certificate: {host}")
    try:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        subject = cert.subject.rfc4514_string()
        expiration_date = cert.not_valid_after
        print(f"Certificate for {host}:")
        print(f"Subject: {subject}")
        print(f"Expiration Date: {expiration_date}")
    except ValueError:
        print("Error: Invalid certificate data.")

def cyberGordon(artifact):
    """
    Processes an artifact (potentially a domain name) using a simulated interaction
    (avoiding web scraping) and adheres to ethical guidelines.

    Args:
        artifact (str): The artifact (e.g., domain name) to process.
        logs_dir (str, optional): The directory to save logs. Defaults to "logs".

    Returns:
        None

    Raises:
        requests.exceptions.RequestException: If an error occurs during the request.
    """

    url = "https://cybergordon.com/request/form"  # Assuming a hypothetical form URL
    form_data = {"obs": artifact}
    print(f"CyberGordon: {artifact}")

    try:
        # Send POST request with form data (simulating interaction)
        response = requests.post(url, data=form_data, allow_redirects=False)
        response.raise_for_status()  # Raise an exception for non-2xx status codes

        # Check if the response is a 302 redirect (simulated behavior)
        if response.status_code == 302:
            cgid = response.headers.get("Location")  # Extract redirect URL
            encoded_cgid = urllib.parse.quote(cgid, safe="")  # URL encode cgid
            url = "https://cybergordon.com"  # Assuming a hypothetical form URL
            try:
                cg_result = requests.get( url + cgid)

                # Simulated log saving (without actual content fetching)
                print(f"Simulated cgid: {encoded_cgid}")
                save_body(artifact, cg_result.text, "cg")
            except KeyError:
                print("did not get cybergordon report.")
        else:
            print(f"Unexpected response status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")

def virustotal_domain_report(domain, api_key):
  """Retrieves domain information from VirusTotal and reports relevant details."""

  base_url = "https://www.virustotal.com/api/v3/domains/{}"
  headers = {"x-apikey": api_key}
  url = base_url.format(domain)

  try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    save_body(url, response.text, "vt")
    data = response.json()
    domain_id = data["data"]["id"]
    try: 
      whois_data = data["data"]["attributes"]["whois"].splitlines()  # Split into lines
      for line in whois_data:
        if line.startswith("Creation Date: "):  # Check if line starts with "Creation Date: "
          print(line)  # Print the matching line
        elif "@" in line:  # Check for email addresses
          print(line)  # Print the matching line
        elif re.match(r": [\d\+\-\(\)]{9,25}$", line):  # Check for a phone number
          print(line)  # Print the matching line
    except KeyError:
      print("WHOIS data not available from VirusTotal for this domain.")

#    # Get detections count and engines
#    detections = data.get("attributes").get("last_analysis_results").get("detected_urls")
#    if detections:
#      print(f"Detections: {detections}")
#      print("Detecting Engines:")
#      for engine in data.get("attributes").get("last_analysis_results").get("scans"):
#        if engine["result"]:
#          print(f"- {engine['engine_name']}")
#
#    # Get categories
#    categories = data.get("categories")
#    if categories:
#      print("Categories:")
#      for category in categories:
#        print(f"- {category}")
#
  except requests.exceptions.RequestException as e:
    print(f"Error fetching VirusTotal data: {e}")

def print_whois_fields(whois):
  # Extract and print fields of interest (adjust as needed)
  emails = whois.get("emails")
  if emails:
    print("  Emails:")
    for email in emails:
      print(f"    - {email}")
  phones = whois.get("phones")
  if phones:
    print("  Phones:")
    for phone in phones:
      print(f"    - {phone}")
  creation_date = whois.get("creation_date")
  if creation_date:
    print(f"  Creation Date: {creation_date}")


# Check for .env file and load variables
if load_dotenv():
    vt_api_key = os.getenv("vtAPIKey")
    misp_api_key = os.getenv("mispAPIKey")
    sans_identity = os.getenv("sansIdentity")

    # Use the loaded variables (example printing)
    print(f"VirusTotal API Key: {vt_api_key}")
    print(f"MISP API Key: {misp_api_key}")
    print(f"SANS Identity: {sans_identity}")
else:
    print("Error: .env file not found")


# Initialize artifacts array
artifacts = []

def is_ip(artifact):
  """Checks if the artifact is a valid IP address."""
  try:
    from ipaddress import ip_address
    ip_address(artifact)
    return True
  except ValueError:
    return False

def is_domain(artifact):
  """Checks if the artifact matches a domain name format."""
  return all(char.isalnum() or char == '.' for char in artifact)

import requests
from urllib.parse import urljoin
import json

def fetch_and_analyze_url(url):
  """Fetches a URL, analyzes the response, and delegates further actions."""

  session = requests.Session()  # Create a session to manage cookies
  compatible_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'
  headers = {'User-Agent': compatible_user_agent}

  try:
    response = session.get(url, headers=headers)
    response.raise_for_status()  # Raise exception for non-2xx status codes

    # Successful response (2xx)
    print("=" * 40)
    print(f"Analyzing URL: {url} (Status Code: {response.status_code})")
    save_body(url, response.text, ".")
    analyze_body(response.status_code, response.text, session.cookies)

  except requests.exceptions.RequestException as e:
    print(f"Error fetching URL: {url} - {e}")

  except requests.exceptions.HTTPError as e:
    # Analyze specific status codes
    status_code = e.response.status_code
    if status_code >= 300 and status_code < 400:
      # Handle redirection (3xx)
      redirected_url = e.response.headers['Location']
      print(f"redirected to: {redirected_url}")
      artifacts.append(urljoin(url, redirected_url))  # Add redirected URL to artifacts
    else:
      # Handle other error codes (4xx, 5xx)
      print(f"Error fetching URL: {url} (Status Code: {status_code})")
      save_body(url, e.response.text)
      analyze_body(status_code, e.response.text)  # Optionally analyze error body

import re

def analyze_body(status_code, body, cookies):
  """Analyzes the response body based on the status code and length."""
  print("-" * 40)
  print("Analyzing body: ")

  print(f"Cookies passed to analyze_body: {cookies}")  # Access cookies in this function
  body_length = len(body)
  print(f"Body length: {body_length} characters")

  if body_length < 1000:
    # Search for URLs in the body (if body is small)
    url_pattern = r"(https?://[^\s]+)"  # Regex pattern for URLs
    urls = re.findall(url_pattern, body)
    if urls:
      print(f"Found URLs:")
      for url in urls:
        print(f"- {url}")
        artifacts.append(url)  # Add found URLs to artifacts
    else:
      print("No URLs found in the body.")
      
  # Search for WordPress (case-insensitive, regardless of body size)
  if "wordpress" in body.lower():
    print("Found potential WordPress usage in the body.")


def save_body(url, body, saveDir):
  """Saves the response body to a file based on the URL."""

  # Access logDir from .env file
  logDir = os.getenv("logDir")

  # Encode URL for filename (optional)
  encoded_url = requests.utils.quote(url, safe='')  # Encode everything
  filename = f"{encoded_url}.html"  # Adjust extension as needed

  # Construct full path with logDir and saveDir
  full_path = os.path.join(logDir, saveDir, filename)

  # Create the directory structure if it doesn't exist
  os.makedirs(os.path.dirname(full_path), exist_ok=True)

  with open(full_path, 'w', encoding='utf-8') as f:
    f.write(body)
  print(f"Body saved to: {full_path}")

def whoisLookup(artifact):
  # Expect a domain or an ip
  try:
    w = whois.whois(artifact)

    # Access specific WHOIS data
    print(f"Domain Name: {w.domain_name}")
    print(f"Creation Date: {w.creation_date}")
    print(f"Registrar: {w.registrar}")

  except Exception as e:
    print(f"An error occurred during WHOIS lookup: {e}")

def analyze_url(artifact):
  """Analyzes a URL artifact (assuming http/https)."""
  print("-" * 40)
  print(f"Analyzing url: {artifact} ")
  from urllib.parse import urlparse
  parsed_url = urlparse(artifact)
  #artifacts.append(parsed_url.netloc)
  analyze_domain(parsed_url.netloc)
  print(f"Analyzing URL: {artifact}")
  print(f"Proto: {parsed_url.scheme}")
  print(f"Host: {parsed_url.netloc}")
  print(f"Path: {parsed_url.path}")
  if parsed_url.scheme == "https":
    port=parsed_url.port or 443
    #getssl(parsed_url.netloc,port)
    subject, not_before, not_after = dissect_certificate(parsed_url.netloc,port)
    print(f"Cert subject: {subject}")
    print(f"Cert issued: {not_before}")
    print(f"Cert expires: {not_after}")
  else:
    print(f"Skipping certificate check for non-HTTPS URL: {artifact}")

  cyberGordon(artifact)
  fetch_and_analyze_url(artifact)

def analyze_domain(artifact):
  """Analyzes a domain name artifact."""
  # Check for name server in .env
  #name_server = os.getenv("nameServer")

  #addr = socket.gethostbyname(artifact)
  #artifacts.append(addr)
  #analyze_ip(addr)

  try:
    addr = socket.gethostbyname(artifact)
    artifacts.append(addr)
  except socket.gaierror as e:
    print(f"Error resolving hostname: {e}")
    # Handle the error, e.g., return None, raise a custom exception, etc.
  except Exception as e:
    print(f"Unexpected error: {e}")
    # Handle unexpected errors


  print("=" * 40)
  print(f"Analyzing Domain: {artifact}")
  #whoisLookup(artifact)
  virustotal_domain_report(artifact,vt_api_key)

def analyze_ip(artifact):
  """Analyzes an IP address artifact."""
  print("=" * 40)
  print(f"Analyzing IP: {artifact}")


# Check if there is at least one argument (script name itself doesn't count)
if len(sys.argv) > 1:
    artifacts.extend(sys.argv[1:])  # Use extend to add each argument individually

    for artifact in artifacts:
        print(f"Analyzing: {artifact}")
        #print(type(artifact))  # Should print <class 'str'>
        """Analyzes the provided artifact based on its format."""
        if artifact.startswith("http") or artifact.startswith("https"):
            analyze_url(artifact)
        elif is_ip(artifact):
            analyze_ip(artifact)
        elif is_domain(artifact):
            analyze_domain(artifact)
        else:
            print(f"Unknown Artifact: {artifact}")

else:
  print("Please provide an artifact name as an argument.")

