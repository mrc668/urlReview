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

import ssl
from datetime import datetime

def save_ssl_certificate(domain, port=443, log_dir="logs/cert"):
  """
  Establishes an SSL connection, saves the certificate, and examines its chain.

  Args:
    domain: The domain name to connect to.
    port: The port number for the connection (default 443).
    log_dir: The directory to save the certificate file (default "logs/cert").
  """
  print("-" * 40)
  try:
    context = ssl.create_default_context()
    print(f"Analyzing certificate: {domain}")

    # Connect to the server with timeout
    with socket.create_connection((domain, port)) as sock:
      sock.settimeout(5)  # Set a timeout for the connection
      conn = context.wrap_socket(sock)

      # Get the certificate chain
      certificate = conn.getpeercert()

      # Create the directory structure if it doesn't exist
      os.makedirs(log_dir, exist_ok=True)

      # Save the certificate
      with open(os.path.join(log_dir, f"{domain}.pem"), "wb") as f:
        f.write(ssl.DER_cert_to_PEM_cert(certificate))

      # Examine the certificate chain
      print(f"--- Certificate Chain for {domain} ---")
      for cert in certificate:
        # Extract and format start and end dates
        start_date = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
        end_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")

        # Check certificate validity (based on current date)
        is_valid = datetime.now() >= datetime.strptime(start_date, "%Y-%m-%d") and datetime.now() <= datetime.strptime(end_date, "%Y-%m-%d")
        print(f"- Issuer: {cert['issuer']}")
        print(f"  - Valid From: {start_date} (IS VALID: {is_valid})")
        print(f"  - Valid Until: {end_date}")

  except (socket.timeout, ssl.SSLError) as e:
    print(f"Error connecting to {domain}:{port}: {e}")

def virustotal_domain_report(domain, api_key):
  """Retrieves domain information from VirusTotal and reports relevant details."""

  base_url = "https://www.virustotal.com/api/v3/domains/{}"
  headers = {"x-apikey": api_key}
  url = base_url.format(domain)

  try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    save_body(url, response.text, "log/vt")
    data = response.json()
    domain_id = data["data"]["id"]
    whois_data = data["data"]["attributes"]["whois"].splitlines()  # Split into lines
    for line in whois_data:
      if line.startswith("Creation Date: "):  # Check if line starts with "Creation Date: "
        print(line)  # Print the matching line
      elif "@" in line:  # Check for email addresses
        print(line)  # Print the matching line
      elif re.match(r": [\d\+\-\(\)]{9,25}$", line):  # Check for a phone number
        print(line)  # Print the matching line



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
    save_body(url, response.text, "log")
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
  from urllib.parse import urlparse
  parsed_url = urlparse(artifact)
  #artifacts.append(parsed_url.netloc)
  analyze_domain(parsed_url.netloc)
  print(f"Analyzing URL: {artifact}")
  print(f"Proto: {parsed_url.scheme}")
  print(f"Host: {parsed_url.netloc} ")
  print(f"Path: {parsed_url.path}")
  if parsed_url.scheme == "https":
    save_ssl_certificate(parsed_url.netloc,parsed_url.port,"log/cert")
  else:
    print(f"Skipping certificate check for non-HTTPS URL: {artifact}")

  fetch_and_analyze_url(artifact)

def analyze_domain(artifact):
  """Analyzes a domain name artifact."""
  # Check for name server in .env
  name_server = os.getenv("nameServer")

  addr = socket.gethostbyname(artifact)
  analyze_ip(addr)

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
        #print(f"Analyzing: {artifact}")
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

