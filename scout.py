# 05/14/2025
import subprocess
import argparse

parser = argparse.ArgumentParser(description="Scout - Basic Recon Tool")

# Arguements
# Domain
parser.add_argument("-d", "--domain", help="Target domain name")
# Full Scan
parser.add_argument("-f", "--full", action="store_true", help="Run a full scan")
# Output to File
parser.add_argument("-o","--output", help="Save output to file")

# Functions
# WHOIS
def run_whois(domain):
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        useful_lines = []
        seen = set()
        
        for line in result.stdout.splitlines():
               line = line.strip().lower()
               if not line or len(line.split()) < 2:
                      continue 
               if ":" in line and any(keyword in line for keyword in [
                      "registrar", "creation date", "registry expiry date", "name server", "domain status"
               ]):
                      if line not in seen:
                             seen.add(line)
                             useful_lines.append(line)
        return "\n".join(useful_lines)

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

if args.output:
       with open(args.output, "w") as f:
              f.write(f"You entered: {domain}\n\n")
              f.write("=== WHOIS INFO ===\n")
              f.write(run_whois(domain))
              f.write("\n=== DIG INFO ===\n")
              f.write(run_dig(domain))
              if args.full:
                       f.write("\n=== PING INFO ===\n")
                       f.write(run_ping(domain))
       print(f"\nResults saved to {args.output}")



