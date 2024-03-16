#!  /usr/bin/python3
import sys

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
    print(f"Analyzing URL: {url} (Status Code: {response.status_code})")
    save_body(url, response.text)
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

def save_body(url, body):
  """Saves the response body to a file based on the URL."""
  # Encode URL for filename (optional)
  encoded_url = requests.utils.quote(url, safe='')  # Encode everything
  filename = f"{encoded_url}.html"  # Adjust extension as needed

  with open(filename, 'w', encoding='utf-8') as f:
    f.write(body)
  print(f"Body saved to: {filename}")

def analyze_url(artifact):
  """Analyzes a URL artifact (assuming http/https)."""
  from urllib.parse import urlparse
  parsed_url = urlparse(artifact)
  artifacts.append(parsed_url.netloc)
  print(f"Analyzing URL: {artifact}")
  print(f"Proto: {parsed_url.scheme}")
  print(f"Host: {parsed_url.netloc} ")
  print(f"Path: {parsed_url.path}")
  fetch_and_analyze_url(artifact)

def analyze_domain(artifact):
  """Analyzes a domain name artifact."""
  print(f"Analyzing Domain: {artifact}")

def analyze_ip(artifact):
  """Analyzes an IP address artifact."""
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

