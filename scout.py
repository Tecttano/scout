#!/usr/bin/env python3
import subprocess, argparse, ipaddress, re, json, urllib.request, ssl, socket, os, sys, time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from functools import partial

parser = argparse.ArgumentParser(description="Scout - Lightweight Recon Tool")
parser.add_argument("-t", "--target", required=True, help="Target domain/IP")
parser.add_argument("-o", "--output", help="Save output to file")
parser.add_argument("--json", action="store_true", help="JSON output")
parser.add_argument("--passive", action="store_true", help="Passive checks only")
parser.add_argument("--headers", action="store_true", help="HTTP headers")
parser.add_argument("--dns-info", action="store_true", help="All DNS records")
parser.add_argument("--mx", action="store_true", help="MX records")
parser.add_argument("--txt", action="store_true", help="TXT records")
parser.add_argument("--spf", action="store_true", help="SPF records")
parser.add_argument("--soa", action="store_true", help="SOA records")
parser.add_argument("--cname", action="store_true", help="CNAME records")
parser.add_argument("--aaaa", action="store_true", help="AAAA (IPv6) records")
parser.add_argument("--ports", action="store_true", help="Scan common ports")
parser.add_argument("--trace", action="store_true", help="Run traceroute")
parser.add_argument("-a", "--all", action="store_true", help="Run all checks")
parser.add_argument("--profile", choices=["quick", "passive", "full"], help="Scan profile")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
parser.add_argument("--timeout", type=int, default=5, help="Timeout in seconds")
parser.add_argument("--threads", type=int, default=10, help="Number of threads for parallel operations")

def validate_target(target):
    """Validate the target is either a valid domain or IP address"""
    # Check if it's an IP address
    try:
        ipaddress.ip_address(target)
        return True, "ip"
    except ValueError:
        pass
    
    # Check if it looks like a domain
    if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$', target):
        return True, "domain"
    
    return False, "Invalid target. Please provide a valid domain name or IP address."

def is_ip(target):
    try: return bool(ipaddress.ip_address(target))
    except ValueError: return False

def run_cmd(cmd, err_msg="Command failed", timeout=None):
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        return subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout).stdout
    except subprocess.CalledProcessError as e:
        return f"{err_msg}: {e.stderr.strip() if e.stderr else 'Command returned non-zero exit status'}"
    except subprocess.TimeoutExpired:
        return f"{err_msg}: Command timed out after {timeout} seconds"
    except FileNotFoundError:
        return f"{err_msg}: Command not found - please ensure {cmd[0]} is installed"
    except Exception as e:
        return f"{err_msg}: {str(e)}"

def log(message, verbose=False):
    if verbose:
        print(f"[*] {message}")

def run_whois(target, timeout=5):
    try:
        raw = run_cmd(["whois", target], "[!] WHOIS failed", timeout=timeout)
        if raw.startswith("[!]"):
            return {"raw": raw, "summary": raw, "json": {"error": raw}}
            
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
    except Exception as e:
        error_msg = f"[!] WHOIS lookup failed: {str(e)}"
        return {"raw": error_msg, "summary": error_msg, "json": {"error": str(e)}}

def format_date(date_str):
    if 'T' in date_str: return date_str.split('T')[0]
    if ' ' in date_str and any(c.isdigit() for c in date_str):
        for part in date_str.split(' '):
            if part.count('-') == 2 or part.count('/') == 2: return part
    return date_str

def run_dns_batch(target, timeout=5, verbose=False):
    """Run DNS lookups in batches with a single function"""
    log("Running DNS checks in batch mode...", verbose)
    dns_info, dns_json = [], {"nameservers": []}
    record_types = ["A", "NS"]
    
    # Add optional record types based on arguments
    global args
    if not is_ip(target):
        if args.mx or args.dns_info:
            record_types.append("MX")
        if args.txt or args.dns_info:
            record_types.append("TXT")
        if args.spf or args.dns_info:
            # SPF is technically stored in TXT records, already covered
            pass
        if args.soa or args.dns_info:
            record_types.append("SOA")
        if args.cname or args.dns_info:
            record_types.append("CNAME")
        if args.aaaa or args.dns_info:
            record_types.append("AAAA")
    
    # Batch-run dig commands in parallel
    with ThreadPoolExecutor(max_workers=min(len(record_types), 5)) as executor:
        # Create a partial function that includes the timeout
        dig_fn = partial(run_dig_query, target=target, timeout=timeout)
        # Map record types to the dig function
        results = list(executor.map(dig_fn, record_types))
    
    # Process results
    for record_type, result in zip(record_types, results):
        if record_type == "A":
            if not result.startswith("[!]"):
                a_records = [line.strip() for line in result.splitlines() if line.strip()]
                if a_records:
                    if len(a_records) == 1:
                        dns_info.append(f"A Record: {a_records[0]}")
                        dns_json["a_record"] = a_records[0]
                    else:
                        dns_info.append(f"A Records: {a_records[0]}")
                        dns_json["a_records"] = a_records
                        for r in a_records[1:]: dns_info.append(f"           {r}")
            else:
                dns_info.append(f"A Record Lookup Error: {result}")
                dns_json["a_record_error"] = result
                
        elif record_type == "NS":
            if not result.startswith("[!]"):
                ns_records = [line.strip().rstrip('.') for line in result.splitlines() if line.strip()]
                if ns_records:
                    dns_info.append(f"NS: {', '.join(ns_records)}")
                    dns_json["nameservers"] = ns_records
            else:
                dns_info.append(f"NS Lookup Error: {result}")
                dns_json["ns_error"] = result
                
        elif record_type == "MX":
            if not result.startswith("[!]"):
                mx_lines = [line for line in result.splitlines() if line.strip()]
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
                
        elif record_type == "TXT":
            if not result.startswith("[!]"):
                txt_records = []
                spf_records = []
                
                for line in result.splitlines():
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
                
        elif record_type == "SOA":
            if not result.startswith("[!]"):
                soa_records = [line.strip() for line in result.splitlines() if line.strip()]
                if soa_records:
                    dns_info.append("SOA Records:")
                    for record in soa_records:
                        dns_info.append(f"  {record}")
                    dns_json["soa_records"] = soa_records
            elif args.soa:
                dns_info.append("No SOA records found")
                
        elif record_type == "CNAME":
            if not result.startswith("[!]") and result.strip():
                cname = result.strip().rstrip('.')
                dns_info.append(f"CNAME: {cname}")
                dns_json["cname"] = cname
                
                # Process sequentially
                current = cname
                seen = {target.lower(), current.lower()}
                chain = [f"{target} → {current}"]
                
                for _ in range(10):
                    next_result = run_cmd(["dig", current, "CNAME", "+short"], "", timeout=timeout)
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
                
        elif record_type == "AAAA":
            if not result.startswith("[!]"):
                aaaa_records = [line.strip() for line in result.splitlines() if line.strip()]
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
    
    # Handle PTR for IP addresses separately
    if is_ip(target):
        try:
            dns_info.append("Target is an IP address, running reverse DNS lookup...")
            ptr_result = run_cmd(["dig", "-x", target, "+short"], "", timeout=timeout)
            if not ptr_result.startswith("[!]"):
                ptr_record = ptr_result.strip().rstrip('.')
                if ptr_record:
                    dns_info.append(f"PTR: {ptr_record}")
                    dns_json["ptr"] = ptr_record
                else:
                    dns_info.append("No reverse DNS record found")
            else:
                dns_info.append(f"PTR Lookup Error: {ptr_result}")
                dns_json["ptr_error"] = ptr_result
        except Exception as e:
            dns_info.append(f"PTR Lookup Error: {str(e)}")
            dns_json["ptr_error"] = str(e)
    
    return {"text": "\n".join(dns_info) or "[!] No DNS records found", "json": dns_json}

def run_dig_query(record_type, target, timeout=5):
    """Helper function to run a single dig query"""
    return run_cmd(["dig", target, record_type, "+short"], "", timeout=timeout)

def run_ping(target, count=4, timeout=10):
    try:
        result = run_cmd(["ping", "-c", str(count), target], "", timeout=timeout)
        if result.startswith("[!]"):
            return {"text": result, "json": {"error": result}}
        
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
    except Exception as e:
        error_msg = f"[!] Ping failed: {str(e)}"
        return {"text": error_msg, "json": {"error": str(e)}}

def get_http_headers(target, timeout=5):
    headers_text, headers_json = [], {"http": {}, "https": {}}
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    
    for protocol in ["http", "https"]:
        try:
            req = urllib.request.Request(f"{protocol}://{target}", method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if protocol == "https" else None) as response:
                headers = {k.lower(): v for k, v in response.info().items()}
                headers_json[protocol] = headers
                headers_text.append(f"--- {protocol.upper()} Headers ---")
                for key, value in headers.items():
                    headers_text.append(f"{key.title()}: {value}")
        except urllib.error.URLError as e:
            error_msg = f"{protocol.upper()} Error: Connection failed"
            if hasattr(e, 'reason'):
                error_msg += f" - {e.reason}"
            elif hasattr(e, 'code'):
                error_msg += f" - HTTP {e.code}"
            headers_text.append(error_msg)
            headers_json[protocol] = {"error": str(e)}
        except socket.timeout:
            error_msg = f"{protocol.upper()} Error: Connection timed out"
            headers_text.append(error_msg)
            headers_json[protocol] = {"error": "Connection timed out"}
        except ssl.SSLError as e:
            error_msg = f"{protocol.upper()} Error: SSL/TLS error - {str(e)}"
            headers_text.append(error_msg)
            headers_json[protocol] = {"error": f"SSL/TLS error: {str(e)}"}
        except Exception as e:
            error_msg = f"{protocol.upper()} Error: {str(e)}"
            headers_text.append(error_msg)
            headers_json[protocol] = {"error": str(e)}
    
    return {"text": "\n".join(headers_text), "json": headers_json}

def scan_port(target, port, timeout=2):
    """Scan a single port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        
        if result == 0:
            service = socket.getservbyport(port) if port < 1024 else "unknown"
            return port, {"status": "open", "service": service}
        return port, {"status": "closed"}
    except Exception as e:
        return port, {"status": "error", "error": str(e)}

def scan_common_ports(target, timeout=2):
    common_ports = [80, 443, 22, 21, 25, 3389, 110, 445, 139, 143]
    results_text = []
    results_json = {}
    
    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Create a partial function with target and timeout
            scan_fn = partial(scan_port, target=target, timeout=timeout)
            # Map ports to the scan function
            scan_results = list(executor.map(scan_fn, common_ports))
        
        # Process results
        for port, result in scan_results:
            if result["status"] == "open":
                service = result.get("service", "unknown")
                results_text.append(f"Port {port} ({service}): OPEN")
                results_json[port] = result
    except Exception as e:
        error_msg = f"Port scanning failed: {str(e)}"
        return {"text": error_msg, "json": {"error": str(e)}}
    
    if not results_text:
        results_text.append("No open common ports found")
    
    return {"text": "\n".join(results_text), "json": results_json}

def run_traceroute(target, max_hops=15, timeout=30):
    try:
        # Use a higher timeout specifically for traceroute
        result = run_cmd(["traceroute", "-m", str(max_hops), "-w", "2", target], "Traceroute failed", timeout=timeout)
        if result.startswith("[!]"):
            return {"text": result, "json": {"error": result}}
        
        trace_json = {"hops": []}
        lines = result.splitlines()
        
        if len(lines) > 1:
            for i, line in enumerate(lines[1:], 1):
                trace_json["hops"].append({"hop": i, "data": line.strip()})
        
        return {"text": result, "json": trace_json}
    except Exception as e:
        error_msg = f"Traceroute failed: {str(e)}"
        return {"text": error_msg, "json": {"error": str(e)}}

def main():
    global args
    args = parser.parse_args()
    target = args.target
    timeout = args.timeout
    verbose = args.verbose
    
    # Input validation
    is_valid, target_type_or_error = validate_target(target)
    if not is_valid:
        print(f"Error: {target_type_or_error}")
        sys.exit(1)
    
    domain_info = target
    
    if args.profile == "quick":
        args.dns_info = True
        args.headers = True
    elif args.profile == "passive":
        args.dns_info = True
        args.headers = True
    elif args.profile == "full":
        args.all = True
    
    if args.all:
        args.dns_info = True
        args.headers = True
        args.ports = True
        args.trace = True
    
    log(f"Starting reconnaissance on {target}", verbose)
    
    # Run tasks in parallel
    tasks = {
        "whois": None,
        "dns": None,
        "ping": None,
        "headers": None,
        "ports": None,
        "trace": None
    }
    
    # Capture function reference and arguments for each task
    task_functions = {
        "whois": (run_whois, (target, timeout)),
        "dns": (run_dns_batch, (target, timeout, verbose)),
        "ping": (run_ping, (target, 4, timeout))
    }
    
    if args.headers or args.all:
        task_functions["headers"] = (get_http_headers, (target, timeout))
    
    if (args.ports or args.all) and not args.passive:
        task_functions["ports"] = (scan_common_ports, (target, timeout))
    
    if (args.trace or args.all) and not args.passive:
        log("Setting up traceroute (this may take up to 30 seconds)...", verbose)
        task_functions["trace"] = (run_traceroute, (target, 15, 30))
    
    # Run tasks in parallel using ThreadPoolExecutor
    results = {}
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Start all tasks concurrently
        futures = {}
        for task_name, (func, func_args) in task_functions.items():
            log(f"Starting {task_name}...", verbose)
            futures[task_name] = executor.submit(func, *func_args)
        
        # Collect results as they complete
        for task_name, future in futures.items():
            try:
                log(f"Waiting for {task_name} to complete...", verbose)
                results[task_name] = future.result()
                log(f"{task_name.capitalize()} completed", verbose)
            except Exception as e:
                log(f"{task_name.capitalize()} failed: {str(e)}", verbose)
                results[task_name] = {"text": f"Error: {str(e)}", "json": {"error": str(e)}}
    
    if args.json:
        json_data = {
            "target": target,
            "target_type": "ip" if is_ip(target) else "domain",
            "domain": domain_info,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ping": results["ping"]["json"],
            "dns": results["dns"]["json"],
            "whois": results["whois"]["json"]
        }
        
        if "headers" in results:
            json_data["headers"] = results["headers"]["json"]
        if "ports" in results:
            json_data["ports"] = results["ports"]["json"]
        if "trace" in results:
            json_data["trace"] = results["trace"]["json"]
        
        print(json.dumps(json_data, indent=None))
    else:
        target_type = "IP Address" if is_ip(target) else "Domain"
        print(f"[TARGET]\n{target_type}: {target}")
        print(f"\n[Domain Info]\n{domain_info}")
        print(f"\n[Ping]\n{results['ping']['text']}")
        print(f"\n[DNS]\n{results['dns']['text']}")
        print(f"\n[WHOIS]\n{results['whois']['summary']}")
        
        if "headers" in results:
            print(f"\n[HTTP Headers]\n{results['headers']['text']}")
        
        if "ports" in results:
            print(f"\n[Common Ports]\n{results['ports']['text']}")
        
        if "trace" in results:
            print(f"\n[Traceroute]\n{results['trace']['text']}")
    
    if args.output:
        if args.json:
            json_data["whois_raw"] = results["whois"]["raw"]
            
            with open(args.output, "w") as f:
                json.dump(json_data, f, indent=2)
        else:
            target_type = "IP Address" if is_ip(target) else "Domain"
            full_output = f"[TARGET]\n{target_type}: {target}\n"
            full_output += f"\n[Domain Info]\n{domain_info}\n"
            full_output += f"[Ping]\n{results['ping']['text']}\n"
            full_output += f"[DNS]\n{results['dns']['text']}\n"
            full_output += f"[WHOIS]\n{results['whois']['summary']}\n"
            
            if "headers" in results:
                full_output += f"[HTTP Headers]\n{results['headers']['text']}\n"
            
            if "ports" in results:
                full_output += f"[Common Ports]\n{results['ports']['text']}\n"
            
            if "trace" in results:
                full_output += f"[Traceroute]\n{results['trace']['text']}\n"
                
            full_output += f"[WHOIS Raw]\n{results['whois']['raw']}"
            
            with open(args.output, "w") as f:
                f.write(full_output)
        
        print(f"\nComplete results saved to {args.output}")

if __name__ == "__main__":
    main()