#!/usr/bin/env python3
# 05/14/2025
import subprocess
import argparse

parser = argparse.ArgumentParser(description="Scout - Basic Recon Tool")

# Arguments
# Domain
parser.add_argument("-d", "--domain", help="Target domain name")
# Full Scan
parser.add_argument("-f", "--full", action="store_true", help="Run a full scan")
# Output to File
parser.add_argument("-o","--output", help="Save output to file")

# Functions
# WHOIS
def run_whois(domain):
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        if result.returncode != 0:
            return f"[!] WHOIS command failed: {result.stderr}"
    except subprocess.TimeoutExpired:
        return f"[!] WHOIS timed out"
    except Exception as e:
        return f"[!] WHOIS error: {str(e)}"
    
    useful_lines = []
    seen = set()
    
    keywords = [
        "domain name", 
        "registry domain",
        "registrar", 
        "creation date", 
        "updated date", 
        "registry expiry date",
        "domain status",
        "name server",
        "dnssec",
        "registrant",
        "admin",
        "tech",
        "registry"
    ]
    
    for line in result.stdout.splitlines():
        original_line = line.strip()
        line_lower = original_line.lower()
        
        if ":" not in line_lower:
            continue
            
        parts = line_lower.split(":", 1)
        field_name = parts[0].strip()
        field_value = parts[1].strip() if len(parts) > 1 else ""
        
        if not field_value:
            continue
            
        is_useful = False
        for keyword in keywords:
            if field_name.startswith(keyword):
                is_useful = True
                break
                
        if not is_useful:
            continue
            
        if line_lower not in seen:
            seen.add(line_lower)
            useful_lines.append(original_line)
    
    if not useful_lines:
        return "[!] No useful WHOIS information found"
    
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

print(f"\nYou entered: {domain}")
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