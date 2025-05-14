# 05/14/2025
import subprocess

domain = input("Enter a domain: ")
print(f"You entered: {domain}")

# WHOIS
whois_result = subprocess.run(["whois", domain], capture_output=True, text=True)

# DIG
dig_result = subprocess.run(["dig", domain, "+short"], capture_output=True, text=True)

# PING
ping_result = subprocess.run(["ping", "-c","4", domain], capture_output=True, text=True)

print("\n=== WHOIS INFO ===")
print(whois_result.stdout)
print(dig_result.stdout)
print(ping_result.stdout)
