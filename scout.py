#!/usr/bin/env python3
# 05/14/2025
import subprocess
import argparse
import ipaddress
import re

parser = argparse.ArgumentParser(description="Scout - Basic Recon Tool")

# Arguments
# Target (IP or Domain)
parser.add_argument("-t", "--target", required=True, help="Target domain name or IP address")
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

# WHOIS with both raw data and summary
def run_whois(target):
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True)
        if result.returncode != 0:
            return {"raw": f"[!] WHOIS command failed: {result.stderr}", "summary": "[!] WHOIS command failed"}
        
        # Get raw output
        raw_output = result.stdout
        
        # Extract key information for summary
        whois_summary = {}
        
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            
            if not value:
                continue
            
            # Extract registrant/owner information
            if key.startswith("registrant org") or key.startswith("registrant organization"):
                whois_summary['registrant'] = value
            
            # Creation date
            elif any(term in key for term in ["creation date", "created"]):
                whois_summary['created'] = value
            
            # Expiration date
            elif any(term in key for term in ["expiry date", "expiration date"]):
                whois_summary['expires'] = value
            
            # Registrar
            elif key == "registrar":
                whois_summary['registrar'] = value
        
        # Format summary output
        summary_lines = []
        if 'registrant' in whois_summary:
            summary_lines.append(f"Registered To: {whois_summary['registrant']}")
        if 'created' in whois_summary:
            summary_lines.append(f"Created: {whois_summary['created']}")
        if 'expires' in whois_summary:
            summary_lines.append(f"Expires: {whois_summary['expires']}")
        if 'registrar' in whois_summary:
            summary_lines.append(f"Registrar: {whois_summary['registrar']}")
        
        summary_output = "\n".join(summary_lines) if summary_lines else "[!] No WHOIS summary information found"
        
        return {"raw": raw_output, "summary": summary_output}
    except Exception as e:
        return {"raw": f"[!] WHOIS error: {str(e)}", "summary": f"[!] WHOIS error: {str(e)}"}

# DNS lookup
def run_dns(target):
    try:
        dns_info = []
        
        # Get A records (IPv4 addresses)
        a_result = subprocess.run(["dig", target, "A", "+short"], capture_output=True, text=True)
        a_records = a_result.stdout.strip().split('\n')
        a_records = [r for r in a_records if r and not r.endswith('.')]  # Filter out CNAME pointers
        if a_records:
            dns_info.append(f"A Record: {a_records[0]}")
            for record in a_records[1:]:
                if record:
                    dns_info.append(f"          {record}")
        
        # Get nameservers
        ns_result = subprocess.run(["dig", target, "NS", "+short"], capture_output=True, text=True)
        ns_records = ns_result.stdout.strip().split('\n')
        if any(ns_records):
            cleaned_ns = [ns.rstrip('.') for ns in ns_records if ns]
            ns_info = ", ".join(cleaned_ns)
            dns_info.append(f"NS: {ns_info}")
        
        # If target is an IP, get reverse DNS
        if is_ip(target):
            ptr_result = subprocess.run(["dig", "-x", target, "+short"], capture_output=True, text=True)
            ptr_record = ptr_result.stdout.strip().rstrip('.')
            if ptr_record:
                dns_info.append(f"PTR: {ptr_record}")
        
        return "\n".join(dns_info) if dns_info else "[!] No DNS records found"
    except Exception as e:
        return f"[!] DNS lookup error: {str(e)}"

# Ping and analyze results
def run_ping(target, count=4):
    try:
        result = subprocess.run(["ping", "-c", str(count), target], capture_output=True, text=True)
        output = result.stdout
        
        # Extract latency
        latency_pattern = r"min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+"
        latency_match = re.search(latency_pattern, output)
        avg_latency = latency_match.group(1) if latency_match else "N/A"
        
        # Extract packet loss
        loss_pattern = r"(\d+)% packet loss"
        loss_match = re.search(loss_pattern, output)
        packet_loss = loss_match.group(1) if loss_match else "N/A"
        
        return f"Count: {count}\nAverage Latency: {avg_latency}ms\nPacket Loss: {packet_loss}%"
    except Exception as e:
        return f"[!] Ping error: {str(e)}"

# Parse arguments
args = parser.parse_args()
target = args.target

# Get all information but store it in variables
domain_info = target
whois_result = run_whois(target)  # Now returns a dictionary with raw and summary
dns_info = run_dns(target)
ping_info = run_ping(target, count=4)

# Display domain info, ping, DNS, and WHOIS summary sections
print(f"[Domain Info]\n{domain_info}")
print(f"\n[Ping]\n{ping_info}")
print(f"\n[DNS]\n{dns_info}")
print(f"\n[WHOIS]\n{whois_result['summary']}")

# Save complete information to file if requested
if args.output:
    full_output = f"[Domain Info]\n{domain_info}\n"
    full_output += f"[Ping]\n{ping_info}\n"
    full_output += f"[DNS]\n{dns_info}\n"
    full_output += f"[WHOIS]\n{whois_result['summary']}\n"
    full_output += f"[WHOIS Raw]\n{whois_result['raw']}"
    
    with open(args.output, "w") as f:
        f.write(full_output)
    print(f"\nComplete results saved to {args.output}")