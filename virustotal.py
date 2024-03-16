import requests

def virustotal_domain_report(domain, api_key):
  """Retrieves domain information from VirusTotal and reports relevant details."""

  base_url = "https://www.virustotal.com/api/v3/domains/{}"
  headers = {"x-apikey": api_key}
  url = base_url.format(domain)

  try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    data = response.json()

    # Get whois information
    whois = data.get("whois")
    if whois:
      print("WHOIS Information:")
      print_whois_fields(whois)

    # Get detections count and engines
    detections = data.get("attributes").get("last_analysis_results").get("detected_urls")
    if detections:
      print(f"Detections: {detections}")
      print("Detecting Engines:")
      for engine in data.get("attributes").get("last_analysis_results").get("scans"):
        if engine["result"]:
          print(f"- {engine['engine_name']}")

    # Get categories
    categories = data.get("categories")
    if categories:
      print("Categories:")
      for category in categories:
        print(f"- {category}")

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

