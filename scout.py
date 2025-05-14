# 05/14/2025
import subprocess

domain = input("Enter a domain: ")
print(f"You entered: {domain}")

# WHOIS
def run_whois(domain):
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        return result.stdout
# DIG
def run_dig(domain):
        result = subprocess.run(["dig", domain, "+short"], capture_output=True, text=True)
        return result.stdout
# PING
def run_ping(domain):
        result = subprocess.run(["ping", "-c", "4", domain], capture_output=True, text=True)
        return result.stdout

print("\n=== INFO ===")
print(run_whois(domain))
print(run_dig(domain))
print(run_ping(domain))
