import socket # socket is a built-in Python library that lets us make network connections
import threading # allows us to run multiple scans at the same time for faster results
import datetime # used to print the time when the scan starts and ends
import subprocess
import re
import requests
from colorama import init, Fore, Style

init() # Initialize colorama - required for colors to work on Windows

# This will store results for all targets, not just one
all_results = {}
lock = threading.Lock() # A lock to prevent multiple threads from writing to the open_ports list at the same time

def get_service(port):
    # Try to find the service name for this port using Python's built in lookup
    # If it can't find one it returns "Unknown"
    try:
        service = socket.getservbyport(port)
        return service
    except:
        return "Unknown"
    
def lookup_cves(service):
    # Query the NVD (National Vulnerability Database) API for known CVEs
    # This is a free public API maintained by the US government
    try:
        # Build the API URL with the service name as the search keyword
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=3"
        
        # Send the request with a timeout so we don't hang forever
        response = requests.get(url, timeout=10)
        data = response.json()

        cves = []

        # Loop through the results and extract CVE ID and description
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            descriptions = item["cve"]["descriptions"]
            
            # Find the English description
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            # Shorten the description to 100 characters so it fits nicely
            short_desc = description[:500] + "..." if len(description) > 500 else description
            cves.append(f"{cve_id}: {short_desc}")

        return cves if cves else ["No known CVEs found"]

    except requests.exceptions.Timeout:
        return ["CVE lookup timed out"]
    except Exception as e:
        return [f"CVE lookup error: {str(e)}"]
    
def fingerprint_os(host):
    # Resolve hostname to IP address first so ping works correctly
    try:
        host = socket.gethostbyname(host)
    except socket.gaierror:
        return "Could not resolve host"
    # Send a ping to the target and analyze the TTL value in the response
    # Different OS's start with different TTL values which helps us identify them
    try:
        # Run a ping command and capture the output
        # -n 1 means send just 1 ping packet
        output = subprocess.check_output(
            ["ping", "-n", "1", host],
            stderr=subprocess.DEVNULL
        ).decode()

        # Use regex to find the TTL value in the ping response
        ttl_match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)

        if ttl_match:
            ttl = int(ttl_match.group(1))

            # Match TTL value to known OS fingerprints
            if ttl <= 64:
                os_guess = "Linux / Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            elif ttl <= 255:
                os_guess = "Cisco / Network Device"
            else:
                os_guess = "Unknown"

            return f"{os_guess} (TTL={ttl})"
        else:
            return "Could not determine OS"

    except subprocess.CalledProcessError:
        return "Host unreachable"
    except Exception as e:
        return f"Error: {str(e)}"

# Checks if a single port is open on the target host
def scan_port(host, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            service = get_service(port)

            # Look up CVEs for this service
            print(f"{Fore.YELLOW}[{host}] Looking up CVEs for {service.upper()}...{Style.RESET_ALL}")
            cves = lookup_cves(service)

            with lock:
                open_ports.append((port, service, cves))
                print(f"{Fore.GREEN}[{host}] Port {port}: OPEN  -->  {service.upper()}{Style.RESET_ALL}")
                for cve in cves:
                    print(f"  {Fore.RED}CVE: {cve}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[{host}] Port {port}: CLOSED{Style.RESET_ALL}")

    except socket.error:
        pass

def scan(host, start_port, end_port):
    open_ports = []

    # Run OS fingerprinting before scanning ports
    print(f"\n{Fore.CYAN}Running OS fingerprint on {host}...{Style.RESET_ALL}")
    os_guess = fingerprint_os(host)
    print(f"{Fore.YELLOW}OS Guess: {os_guess}{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}Scanning {host} from port {start_port} to {end_port}...{Style.RESET_ALL}\n")

    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Store results including the OS guess
    all_results[host] = {
        "os": os_guess,
        "open_ports": open_ports
    }

    print(f"\n{Fore.CYAN}Finished scanning {host}!{Style.RESET_ALL}")
    print(f"\n{'Port':<10} {'Service':<20} {'CVEs'}")
    print(f"{'-'*60}")

    for port, service, cves in sorted(open_ports):
        print(f"{Fore.GREEN}{port:<10} {service.upper():<20}{Style.RESET_ALL}")
        for cve in cves:
            print(f"  {Fore.RED}{cve}{Style.RESET_ALL}")

def save_results(start_port, end_port):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write(f"Port Scan Results\n")
        f.write(f"=================\n")
        f.write(f"Scanned At:  {timestamp}\n")
        f.write(f"Port Range:  {start_port} - {end_port}\n")
        f.write(f"=================\n\n")

        for host, data in all_results.items():
            f.write(f"\nTarget: {host}\n")
            f.write(f"OS Guess: {data['os']}\n")
            f.write(f"{'-'*40}\n")
            if data["open_ports"]:
                for port, service, cves in sorted(data["open_ports"]):
                    f.write(f"Port {port}: OPEN  -->  {service.upper()}\n")
                    for cve in cves:
                        f.write(f"  CVE: {cve}\n")
            else:
                f.write("No open ports found.\n")

    print(f"\n{Fore.YELLOW}Results saved to {filename}{Style.RESET_ALL}")

def load_targets(filename):
    # Open the targets file and read each line as a target
    # strip() removes any extra whitespace or newlines from each line
    try:
        with open(filename, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    except FileNotFoundError:
        print(f"{Fore.RED}Error: {filename} not found!{Style.RESET_ALL}")
        return []

# Main program starts here ---
# Ask the user to type in the target (IP address or hostname like "localhost")
targets = load_targets("targets.txt")

if not targets:
    print("No targets found. Please add IPs to targets.txt")
else:
    print(f"{Fore.CYAN}Loaded {len(targets)} target(s): {', '.join(targets)}{Style.RESET_ALL}")

    start = int(input("Enter start port: "))
    end = int(input("Enter end port: "))

    for target in targets:
        scan(target, start, end)

    save = input("\nSave results to file? (y/n): ")
    if save.lower() == "y":
        save_results(start, end)