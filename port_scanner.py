from enum import unique
import socket # socket is a built-in Python library that lets us make network connections
import threading # allows us to run multiple scans at the same time for faster results
import datetime # used to print the time when the scan starts and ends
import subprocess
import re
import requests
import argparse
from colorama import init, Fore, Style

init() # Initialize colorama - required for colors to work on Windows

# This will store results for all targets, not just one
all_results = {}
lock = threading.Lock() # A lock to prevent multiple threads from writing to the open_ports list at the same time

# Looks up the name of the service running on a given port. 
# Uses Python's built in socket library to match port numbers to service names.
# Returns 'Unknown' if the port is not recognized.
def get_service(port):
    try:
        service = socket.getservbyport(port)
        return service
    except:
        return "Unknown"

#  Queries the NVD (National Vulnerability Database) API for known CVEs related to a service.
#  Takes the service name as a search keyword and returns the top 3 matching CVEs.
#  Returns a list of CVE IDs with short descriptions.
def lookup_cves(service):
    try:
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

# Attempts to identify the operating system of the target host using TTL analysis.
# Sends a ping to the target and reads the TTL (Time To Live) value in the response.
# Different operating systems use different default TTL values:
# TTL 64  = Linux / Unix
# TTL 128 = Windows
# TTL 255 = Cisco / Network Device
# Returns a string with the OS guess and TTL value.
def fingerprint_os(host):
    # Resolve hostname to IP address first so ping works correctly
    try:
        host = socket.gethostbyname(host)
    except socket.gaierror:
        return "Could not resolve host"
    # Send a ping to the target and analyze the TTL value in the response
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

# Checks if a single port is open on the target host.
# Creates a TCP socket and attempts to connect to the port.
# If the connection succeeds the port is open and we look up its service and CVEs.
# If the connection fails the port is closed.
# Results are stored in the open_ports list which is shared across threads.
# A lock is used to prevent multiple threads from writing to the list at the same time.
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

#  Main scanning function that coordinates the full scan of a single target.
#  First runs OS fingerprinting to identify the target's operating system.
#  Then creates a thread for each port in the range and scans them all simultaneously.
#  Waits for all threads to finish before displaying and storing the results.
#  Results are stored in the all_results dictionary for later saving to a file.
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

# Saves all scan results to a timestamped text file.
# Includes the target, OS guess, open ports, services, and CVEs for each host.
# The filename includes the date and time so each scan has a unique file.
def save_results(filename, start_port, end_port):
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

# Reads a list of target IP addresses or hostnames from a text file.
# Each line in the file should contain one target.
# Strips whitespace and blank lines automatically.
# Returns a list of targets, or an empty list if the file is not found.
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
 
# Parses a port range string like '1-500' into a start and end port number.
# Splits the string on the dash character and converts both parts to integers.
# Returns a tuple of (start_port, end_port).
def parse_ports(port_string):
    try:
        start, end = port_string.split("-")
        return int(start), int(end)
    except:
        print(f"{Fore.RED}Invalid port range. Use format: 1-500{Style.RESET_ALL}")
        exit()

# Sets up the CLI argument parser using Python's built in argparse library.
# Defines the following arguments:
# --target  : single target IP or hostname
# --file    : text file containing list of targets
# --ports   : port range in format start-end (default: 1-1024)
# --output  : filename to save results to (optional)
# At least one of --target or --file must be provided.
def setup_argparse():
    # Create the argument parser with a description shown in the help menu
    parser = argparse.ArgumentParser(
        description="Python Port Scanner - Multithreaded scanner with CVE lookup and OS fingerprinting"
    )

    # --target lets the user specify a single target directly
    parser.add_argument(
        "--target",
        help="Single target IP or hostname (e.g. --target 192.168.1.1)"
    )

    # --file lets the user specify a text file with multiple targets
    parser.add_argument(
        "--file",
        help="Text file containing list of targets (e.g. --file targets.txt)"
    )

    # --ports lets the user specify a port range, defaults to 1-1024
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range to scan in format start-end (default: 1-1024)"
    )

    # --output lets the user specify a filename to save results to
    parser.add_argument(
        "--output",
        help="Filename to save results to (e.g. --output results.txt)"
    )

    return parser.parse_args()


# Main program starts here ---
args = setup_argparse()

# Build the list of targets from --target or --file
targets = []

if args.target:
    targets.append(args.target)

if args.file:
    targets.extend(load_targets(args.file))

if not targets:
    print(f"{Fore.RED}Error: please provide a target using --target or --file{Style.RESET_ALL}")
    exit()

# Parse the port range
start, end = parse_ports(args.ports)

print(f"{Fore.CYAN}Loaded {len(targets)} target(s): {', '.join(targets)}{Style.RESET_ALL}")

# Scan each target
for target in targets:
    scan(target, start, end)

# Save results if --output was provided, otherwise ask the user
if args.output:
    save_results(args.output, start, end)
else:
    save = input("\nSave results to file? (y/n): ")
    if save.lower() == "y":
        filename = f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        save_results(filename, start, end)