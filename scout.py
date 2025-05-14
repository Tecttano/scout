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
    
    # Data structure to organize the WHOIS information
    data = {
        'domain': '',
        'created': '',
        'updated': '',
        'expires': '',
        'registrar': '',
        'registrar_email': '',
        'registrar_phone': '',
        'owner': '',
        'owner_email': '',
        'owner_phone': '',
        'owner_address': '',
        'nameservers': [],
        'dnssec': ''
    }
    
    # Extract information from WHOIS output
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        
        if not value:
            continue
            
        if key.startswith("domain name"):
            data['domain'] = value
        
        elif any(c in key for c in ["creation date", "created"]):
            data['created'] = value
        elif "updated date" in key:
            data['updated'] = value
        elif any(e in key for e in ["expiry date", "expiration date"]):
            data['expires'] = value
            
        elif key == "registrar":
            data['registrar'] = value
        elif "registrar abuse contact email" in key:
            data['registrar_email'] = value
        elif "registrar abuse contact phone" in key:
            data['registrar_phone'] = value
            
        elif "registrant organization" in key or "registrant org" in key:
            data['owner'] = value
        elif "registrant email" in key:
            data['owner_email'] = value
        elif "registrant phone" in key:
            data['owner_phone'] = value
        elif "registrant street" in key:
            address_parts = [value]
            data['owner_address'] = value
            
        elif "registrant city" in key and 'owner_address' in data:
            data['owner_address'] += f", {value}"
        elif ("registrant state" in key or "registrant province" in key) and 'owner_address' in data:
            data['owner_address'] += f", {value}"
        elif ("registrant postal" in key or "registrant zip" in key) and 'owner_address' in data:
            data['owner_address'] += f" {value}"
        elif "registrant country" in key and 'owner_address' in data:
            data['owner_address'] += f", {value}"
            
        elif "name server" in key:
            if value.lower() not in [ns.lower() for ns in data['nameservers']]:
                data['nameservers'].append(value)
                
        elif key == "dnssec":
            data['dnssec'] = value
    
    # Format the output
    output = []
    if data['domain']:
        output.append(f"Domain:         {data['domain']}")
    if data['created']:
        output.append(f"Created:        {data['created']}")
    if data['updated']:
        output.append(f"Updated:        {data['updated']}")
    if data['expires']:
        output.append(f"Expires:        {data['expires']}")
    if data['registrar']:
        output.append(f"Registrar:      {data['registrar']}")
    if data['registrar_email']:
        output.append(f"Registrar Email:{data['registrar_email']}")
    if data['registrar_phone']:
        output.append(f"Registrar Phone:{data['registrar_phone']}")
    if data['owner']:
        output.append(f"Owner:          {data['owner']}")
    if data['owner_email']:
        output.append(f"Owner Email:    {data['owner_email']}")
    if data['owner_phone']:
        output.append(f"Owner Phone:    {data['owner_phone']}")
    if data['owner_address']:
        output.append(f"Owner Address:  {data['owner_address']}")
    
    # Add nameservers
    if data['nameservers']:
        ns_lines = [f"Nameservers:    {data['nameservers'][0]}"]
        for ns in data['nameservers'][1:]:
            ns_lines.append(f"                {ns}")
        output.extend(ns_lines)
    
    if data['dnssec']:
        output.append(f"DNSSEC:         {data['dnssec']}")
    
    if not output:
        return "[!] No useful WHOIS information found"
    
    return "\n".join(output)

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
target_type = "IP address" if target_is_ip else "domain"

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