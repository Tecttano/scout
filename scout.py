#!/usr/bin/env python3
# 05/14/2025
import subprocess
import argparse
import ipaddress

parser = argparse.ArgumentParser(description="Scout - Basic Recon Tool")

# Arguments
# Target (IP or Domain)
parser.add_argument("-t", "--target", required=True, help="Target domain name or IP address")
# Full Scan
parser.add_argument("-f", "--full", action="store_true", help="Run a full scan")
# Output to File
parser.add_argument("-o", "--output", help="Save output to file")

# Functions

# Check if target is an IP
def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

# WHOIS
def run_whois(target):
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True)
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
        "registry",
        "country",
        "address",
        "status",
        "last-modified",
        "source",
        "email",
        "phone",
        "e-mail",
        "netname",
        "netrange",
        "inetnum",
        "org",
        "cidr"
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

# Dig
def run_dig(target):
    # For IPs, do a reverse lookup instead
    if is_ip(target):
        result = subprocess.run(["dig", "-x", target, "+short"], capture_output=True, text=True)
        if not result.stdout.strip():
            return "[!] No reverse DNS records found"
        return result.stdout
    else:
        # For domains, do a forward lookup
        result = subprocess.run(["dig", target, "+short"], capture_output=True, text=True)
        if not result.stdout.strip():
            return "[!] No DNS records found"
        return result.stdout
    
# Ping
def run_ping(target):
    result = subprocess.run(["ping", "-c", "4", target], capture_output=True, text=True)
    return result.stdout

# Parse arguments
args = parser.parse_args()
target = args.target

# Detect if target is an IP address or domain
target_is_ip = is_ip(target)
target_type = "IP address" if is_ip(target) else "domain"

print(f"\nTarget {target_type}: {target}")
print("\n=== WHOIS INFO ===")
print(run_whois(target))

# Use dig appropriately for IP or domain
print(f"\n=== {'REVERSE DNS' if target_is_ip else 'DNS INFO'} ===")
print(run_dig(target))

if args.full:
    print("\n=== PING INFO ===")
    print(run_ping(target))

# Save to file if requested
if args.output:
    with open(args.output, "w") as f:
        f.write(f"Target {target_type}: {target}\n\n")
        f.write("=== WHOIS INFO ===\n")
        f.write(run_whois(target))
        f.write(f"\n=== {'REVERSE DNS' if target_is_ip else 'DNS INFO'} ===\n")
        f.write(run_dig(target))
        if args.full:
            f.write("\n=== PING INFO ===\n")
            f.write(run_ping(target))
    print(f"\nResults saved to {args.output}")