import requests
from bs4 import BeautifulSoup  # For parsing HTML response

def whois(domain):
  """Queries a web-based whois service for domain information and reports specific fields."""

  # Replace with your preferred whois service URL (e.g., https://whois.domaintools.com/)
  whois_url = f"https://whois.domaintools.com/{domain}"

  try:
    response = requests.get(whois_url)
    response.raise_for_status()  # Raise exception for non-2xx status codes

    # Parse HTML response (adjust selectors based on the service)
    soup = BeautifulSoup(response.content, 'html.parser')
    email_elements = soup.find_all('span', text='Email:')
    phone_elements = soup.find_all('span', text='Phone:')
    creation_date_element = soup.find('span', text='Creation Date:')

    # Extract information (adjust based on HTML structure)
    emails = [element.find_next_sibling('span').text.strip() for element in email_elements]
    phones = [element.find_next_sibling('span').text.strip() for element in phone_elements]
    creation_date = creation_date_element.find_next_sibling('span').text.strip() if creation_date_element else None

    # Print information
    if emails:
      print(f"  Emails:")
      for email in emails:
        print(f"    - {email}")
    if phones:
      print(f"  Phones:")
      for phone in phones:
        print(f"    - {phone}")
    if creation_date:
      print(f"  Creation Date: {creation_date}")

  except requests.exceptions.RequestException as e:
    print(f"Error fetching whois information: {e}")
  except AttributeError:
    print(f"Error parsing whois response (may require adjustments for service structure)")

