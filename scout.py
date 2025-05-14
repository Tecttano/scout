# 05/14/2025
import subprocess
import argparse

parser = argparse.ArgumentParser(description="Scout - Basic Recon Tool")

# Arguements
# Domain
parser.add_argument("-d", "--domain", help="Target domain name")
# Full Scan
parser.add_argument("-f", "--full", action="store_true", help="Run a full scan")

# Functions
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

# Parse
args = parser.parse_args()
domain = args.domain
if not domain:
        print("You must provide a domain with -d or --domain")
        exit()

print (f"\nYou entered: {domain}")
print("\n=== WHOIS INFO ===")
print(run_whois(domain))
print("\n=== DIG INFO ===")
print(run_dig(domain))

if args.full:
    print("\n=== PING INFO ===")
    print(run_ping(domain))

