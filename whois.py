import socket
import re

def whois(domain):
  """Queries whois servers for a domain and reports specific fields."""

  # Base whois server URL
  whois_server = f"whois.domaintools.com/{domain}"

  try:
    # Connect to whois server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect(('whois.domaintools.com', 43))
      s.sendall(f"whois {domain}\r\n".encode('utf-8'))
      response = b''
      while True:
        chunk = s.recv(1024)
        if not chunk:
          break
        response += chunk

    # Decode response and search for relevant fields
    decoded_response = response.decode('utf-8')
    email_pattern = r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})"
    phone_pattern = r"[\+\d\-\(\) ]{7,}"  #簡易な電話番号パターン (can be refined)
    creation_pattern = r"Creation Date: (.*)"

    for line in decoded_response.splitlines():
      # Extract email addresses
      matches = re.findall(email_pattern, line)
      if matches:
        for email in matches:
          print(f"  Email: {email}")

      # Extract phone numbers (adjust pattern for specific needs)
      matches = re.findall(phone_pattern, line)
      if matches:
        for phone in matches:
          print(f"  Phone: {phone}")

      # Extract creation date
      match = re.search(creation_pattern, line)
      if match:
        print(f"  Creation Date: {match.group(1)}")

  except Exception as e:
    print(f"Error querying whois server: {e}")


