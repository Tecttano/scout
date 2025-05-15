# scout
scout is a lightweight Linux-native CLI recon tool that performs quick passive and active recon on domains or IPs

Features

DNS records (A, NS, MX, TXT, SPF, SOA, CNAME, AAAA)
WHOIS information
Common port scanning
HTTP headers analysis
Ping statistics
Traceroute mapping
Parallel execution

Usage - 
python3 scout.py -t example.com            # Basic scan
python3 scout.py -t 8.8.8.8 --ports        # Scan with port check
python3 scout.py -t example.com -a         # All checks
python3 scout.py -t domain.com -o results  # Save to file
python3 scout.py -t example.com --json     # JSON output

Options - 
-t, --target      Target domain/IP (required)
--passive         Passive checks only
--dns-info        All DNS records
--headers         HTTP headers
--ports           Scan common ports
--trace           Run traceroute
-a, --all         Run all checks
--profile         Scan profile (quick, passive, full)
-v, --verbose     Verbose output
--timeout         Timeout in seconds (default: 5)
--threads         Max threads (default: 10)

Requirements - 
Python 3.6+
Standard Unix tools: dig, whois, ping, traceroute

Installation
git clone https://github.com/Tecttano/scout.git
cd scout
chmod +x scout.py