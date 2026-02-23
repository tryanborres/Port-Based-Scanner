import socket # socket is a built-in Python library that lets us make network connections
import threading # allows us to run multiple scans at the same time for faster results
import datetime # used to print the time when the scan starts and ends
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

# Checks if a single port is open on the target host
def scan_port(host, port, open_ports):
    # open_ports is now passed in so each target has its own list
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            service = get_service(port)
            with lock:
                open_ports.append((port, service))
                print(f"{Fore.GREEN}[{host}] Port {port}: OPEN  -->  {service.upper()}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[{host}] Port {port}: CLOSED{Style.RESET_ALL}")

    except socket.error:
        pass

def scan(host, start_port, end_port):
    # Each target gets its own open_ports list
    open_ports = []
    print(f"\n{Fore.CYAN}Scanning {host} from port {start_port} to {end_port}...{Style.RESET_ALL}\n")

    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Store this target's results in the all_results dictionary
    all_results[host] = open_ports

    print(f"\n{Fore.CYAN}Finished scanning {host}!{Style.RESET_ALL}")
    print(f"\n{'Port':<10} {'Service'}")
    print(f"{'-'*20}")

    for port, service in sorted(open_ports):
        print(f"{Fore.GREEN}{port:<10} {service.upper()}{Style.RESET_ALL}")

def save_results(start_port, end_port):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write(f"Port Scan Results\n")
        f.write(f"=================\n")
        f.write(f"Scanned At:  {timestamp}\n")
        f.write(f"Port Range:  {start_port} - {end_port}\n")
        f.write(f"=================\n\n")

        # Loop through each target and write its results
        for host, open_ports in all_results.items():
            f.write(f"\nTarget: {host}\n")
            f.write(f"{'-'*20}\n")
            if open_ports:
                for port, service in sorted(open_ports):
                    f.write(f"Port {port}: OPEN  -->  {service.upper()}\n")
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

    # Loop through each target and scan it one by one
    for target in targets:
        scan(target, start, end)

    save = input("\nSave results to file? (y/n): ")
    if save.lower() == "y":
        save_results(start, end)