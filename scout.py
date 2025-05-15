#!/usr/bin/env python3
import subprocess, argparse, ipaddress, re, json, urllib.request, ssl
from urllib.error import URLError

parser = argparse.ArgumentParser(description="Scout - Basic Recon Tool")
parser.add_argument("-t", "--target", required=True, help="Target domain/IP")
parser.add_argument("-o", "--output", help="Save output to file")
parser.add_argument("--json", action="store_true", help="JSON output")
parser.add_argument("--headers", action="store_true", help="HTTP headers")
parser.add_argument("--dns-info", action="store_true", help="All DNS records")
parser.add_argument("--mx", action="store_true", help="MX records")
parser.add_argument("--txt", action="store_true", help="TXT records")
parser.add_argument("--spf", action="store_true", help="SPF records")
parser.add_argument("--soa", action="store_true", help="SOA records")
parser.add_argument("--cname", action="store_true", help="CNAME records")
parser.add_argument("--aaaa", action="store_true", help="AAAA (IPv6) records")

def is_ip(target):
    try: return bool(ipaddress.ip_address(target))
    except ValueError: return False

def run_cmd(cmd, err_msg="Command failed"):
    try: return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except: return err_msg

def run_whois(target):
    raw = run_cmd(["whois", target], "[!] WHOIS failed")
    summary, json_data = {}, {}
    
    for line in raw.splitlines():
        if not line.strip() or ":" not in line: continue
        
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if not value: continue
        
        if "registrant org" in key or "registrant organization" in key:
            summary['registrant'] = json_data['registered_to'] = value
        elif any(x in key for x in ["creation date", "created"]):
            date = format_date(value)
            summary['created'] = json_data['created'] = date
        elif any(x in key for x in ["expiry date", "expiration date"]):
            date = format_date(value)
            summary['expires'] = json_data['expires'] = date
        elif key == "registrar":
            summary['registrar'] = json_data['registrar'] = value
    
    lines = []
    for k, label in [('registrant', 'Registered To'), ('created', 'Created'), 
                     ('expires', 'Expires'), ('registrar', 'Registrar')]:
        if k in summary: lines.append(f"{label}: {summary[k]}")
    
    summary_text = "\n".join(lines) or "[!] No WHOIS summary information found"
    return {"raw": raw, "summary": summary_text, "json": json_data}

def format_date(date_str):
    if 'T' in date_str: return date_str.split('T')[0]
    if ' ' in date_str and any(c.isdigit() for c in date_str):
        for part in date_str.split(' '):
            if part.count('-') == 2 or part.count('/') == 2: return part
    return date_str

def run_dns(target):
    dns_info, dns_json = [], {"nameservers": []}
    
    a_result = run_cmd(["dig", target, "A", "+short"], "")
    if a_result and not a_result.startswith("[!]"):
        a_records = [line.strip() for line in a_result.splitlines() if line.strip()]
        if a_records:
            if len(a_records) == 1:
                dns_info.append(f"A Record: {a_records[0]}")
                dns_json["a_record"] = a_records[0]
            else:
                dns_info.append(f"A Records: {a_records[0]}")
                dns_json["a_records"] = a_records
                for r in a_records[1:]: dns_info.append(f"           {r}")
    
    ns_result = run_cmd(["dig", target, "NS", "+short"], "")
    if ns_result and not ns_result.startswith("[!]"):
        ns_records = [line.strip().rstrip('.') for line in ns_result.splitlines() if line.strip()]
        if ns_records:
            dns_info.append(f"NS: {', '.join(ns_records)}")
            dns_json["nameservers"] = ns_records
    
    if (args.mx or args.dns_info) and not is_ip(target):
        mx_result = run_cmd(["dig", target, "MX", "+short"], "")
        if mx_result and not mx_result.startswith("[!]"):
            mx_lines = [line for line in mx_result.splitlines() if line.strip()]
            cleaned_mx = []
            
            for mx in mx_lines:
                parts = mx.split()
                if len(parts) > 1:
                    mx_domain = parts[1].rstrip('.')
                    cleaned_mx.append(f"{parts[0]} {mx_domain}")
            
            if cleaned_mx:
                dns_info.append(f"MX Records:")
                for mx in cleaned_mx:
                    dns_info.append(f"  {mx}")
                dns_json["mx_records"] = cleaned_mx
        elif args.mx:
            dns_info.append("No MX records found")
    
    if (args.txt or args.dns_info) and not is_ip(target):
        txt_result = run_cmd(["dig", target, "TXT", "+short"], "")
        if txt_result and not txt_result.startswith("[!]"):
            txt_records = []
            spf_records = []
            
            for line in txt_result.splitlines():
                if line.strip():
                    clean_txt = line.strip('"')
                    txt_records.append(clean_txt)
                    if 'v=spf1' in line.lower() and (args.spf or args.dns_info):
                        spf_records.append(clean_txt)
            
            if txt_records:
                dns_info.append(f"TXT Records:")
                for record in txt_records:
                    dns_info.append(f"  {record}")
                dns_json["txt_records"] = txt_records
            
            if (args.spf or args.dns_info):
                if spf_records:
                    dns_info.append(f"SPF Records:")
                    for record in spf_records:
                        dns_info.append(f"  {record}")
                    dns_json["spf_records"] = spf_records
                elif args.spf:
                    dns_info.append("No SPF records found")
        elif args.txt:
            dns_info.append("No TXT records found")
    
    if (args.soa or args.dns_info) and not is_ip(target):
        soa_result = run_cmd(["dig", target, "SOA", "+short"], "")
        if soa_result and not soa_result.startswith("[!]"):
            soa_records = [line.strip() for line in soa_result.splitlines() if line.strip()]
            if soa_records:
                dns_info.append("SOA Records:")
                for record in soa_records:
                    dns_info.append(f"  {record}")
                dns_json["soa_records"] = soa_records
        elif args.soa:
            dns_info.append("No SOA records found")
    
    if (args.cname or args.dns_info) and not is_ip(target):
        cname_result = run_cmd(["dig", target, "CNAME", "+short"], "")
        if cname_result and not cname_result.startswith("[!]") and cname_result.strip():
            cname = cname_result.strip().rstrip('.')
            dns_info.append(f"CNAME: {cname}")
            dns_json["cname"] = cname
            
            current = cname
            seen = {target.lower(), current.lower()}
            chain = [f"{target} → {current}"]
            
            for _ in range(10):
                next_result = run_cmd(["dig", current, "CNAME", "+short"], "")
                if not next_result or next_result.startswith("[!]") or not next_result.strip():
                    break
                    
                next_cname = next_result.strip().rstrip('.')
                if not next_cname or next_cname.lower() in seen:
                    break
                    
                seen.add(next_cname.lower())
                chain.append(f"{current} → {next_cname}")
                current = next_cname
            
            if len(chain) > 1:
                dns_info.append("CNAME Chain:")
                for link in chain:
                    dns_info.append(f"  {link}")
                dns_json["cname_chain"] = chain
        elif args.cname:
            dns_info.append("No CNAME records found")
    
    if (args.aaaa or args.dns_info) and not is_ip(target):
        aaaa_result = run_cmd(["dig", target, "AAAA", "+short"], "")
        if aaaa_result and not aaaa_result.startswith("[!]"):
            aaaa_records = [line.strip() for line in aaaa_result.splitlines() if line.strip()]
            if aaaa_records:
                if len(aaaa_records) == 1:
                    dns_info.append(f"AAAA Record: {aaaa_records[0]}")
                    dns_json["aaaa_record"] = aaaa_records[0]
                else:
                    dns_info.append(f"AAAA Records:")
                    for record in aaaa_records:
                        dns_info.append(f"  {record}")
                    dns_json["aaaa_records"] = aaaa_records
            elif args.aaaa:
                dns_info.append("No IPv6 (AAAA) records found")
    
    if is_ip(target):
        dns_info.append("Target is an IP address, running reverse DNS lookup...")
        ptr_result = run_cmd(["dig", "-x", target, "+short"], "")
        ptr_record = ptr_result.strip().rstrip('.')
        if ptr_record:
            dns_info.append(f"PTR: {ptr_record}")
            dns_json["ptr"] = ptr_record
        else:
            dns_info.append("No reverse DNS record found")
    
    return {"text": "\n".join(dns_info) or "[!] No DNS records found", "json": dns_json}

def run_ping(target, count=4):
    result = run_cmd(["ping", "-c", str(count), target], "[!] Ping failed")
    if result == "[!] Ping failed": return {"text": result, "json": {}}
    
    latency = re.search(r"min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+", result)
    loss = re.search(r"(\d+)% packet loss", result)
    
    avg_latency = latency.group(1) if latency else "N/A"
    packet_loss = loss.group(1) if loss else "N/A"
    
    text = f"Count: {count}\nAverage Latency: {avg_latency}ms\nPacket Loss: {packet_loss}%"
    json_data = {
        "count": count,
        "avg_latency_ms": float(avg_latency) if avg_latency != "N/A" else None,
        "packet_loss": f"{packet_loss}%"
    }
    
    return {"text": text, "json": json_data}

def get_http_headers(target):
    headers_text, headers_json = [], {"http": {}, "https": {}}
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    
    for protocol in ["http", "https"]:
        try:
            req = urllib.request.Request(f"{protocol}://{target}", method="HEAD")
            with urllib.request.urlopen(req, timeout=5, context=ctx if protocol == "https" else None) as response:
                headers = {k.lower(): v for k, v in response.info().items()}
                headers_json[protocol] = headers
        except Exception as e:
            headers_json[protocol] = {"error": str(e)}
    
    all_headers = {}
    for protocol in ["http", "https"]:
        if "error" not in headers_json[protocol]:
            all_headers.update(headers_json[protocol])
    
    for key, value in all_headers.items():
        headers_text.append(f"{key.title()}: {value}")
    
    if not headers_text:
        for protocol in ["http", "https"]:
            if "error" in headers_json[protocol]:
                headers_text.append(f"{protocol.upper()} Error: {headers_json[protocol]['error']}")
    
    return {"text": "\n".join(headers_text), "json": headers_json}

args = parser.parse_args()
target = args.target
domain_info = target
whois_result = run_whois(target)
dns_result = run_dns(target)
ping_result = run_ping(target)
headers_result = get_http_headers(target) if args.headers else None

if args.json:
    json_data = {
        "target": target,
        "target_type": "ip" if is_ip(target) else "domain",
        "domain": domain_info,
        "ping": ping_result["json"],
        "dns": dns_result["json"],
        "whois": whois_result["json"]
    }
    
    if headers_result: json_data["headers"] = headers_result["json"]
    print(json.dumps(json_data, indent=None))
else:
    target_type = "IP Address" if is_ip(target) else "Domain"
    print(f"[TARGET]\n{target_type}: {target}")
    print(f"\n[Domain Info]\n{domain_info}")
    print(f"\n[Ping]\n{ping_result['text']}")
    print(f"\n[DNS]\n{dns_result['text']}")
    print(f"\n[WHOIS]\n{whois_result['summary']}")
    
    if headers_result:
        print(f"\n[HTTP Headers]\n{headers_result['text']}")

if args.output:
    if args.json:
        json_data = {
            "target": target,
            "target_type": "ip" if is_ip(target) else "domain",
            "domain": domain_info,
            "ping": ping_result["json"],
            "dns": dns_result["json"],
            "whois": whois_result["json"]
        }
        
        if headers_result: json_data["headers"] = headers_result["json"]
        json_data["whois_raw"] = whois_result["raw"]
        
        with open(args.output, "w") as f:
            json.dump(json_data, f, indent=2)
    else:
        target_type = "IP Address" if is_ip(target) else "Domain"
        full_output = f"[TARGET]\n{target_type}: {target}\n"
        full_output += f"\n[Domain Info]\n{domain_info}\n"
        full_output += f"[Ping]\n{ping_result['text']}\n"
        full_output += f"[DNS]\n{dns_result['text']}\n"
        full_output += f"[WHOIS]\n{whois_result['summary']}\n"
        
        if headers_result:
            full_output += f"[HTTP Headers]\n{headers_result['text']}\n"
            
        full_output += f"[WHOIS Raw]\n{whois_result['raw']}"
        
        with open(args.output, "w") as f:
            f.write(full_output)
    
    print(f"\nComplete results saved to {args.output}")