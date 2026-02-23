import socket # socket is a built-in Python library that lets us make network connections
import threading # allows us to run multiple scans at the same time for faster results
import datetime # used to print the time when the scan starts and ends

open_ports = [] # This list will store the open ports we find

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
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            # Look up the service name when we find an open port
            service = get_service(port)
            with lock: # Use the lock to safely add the open port to our list without conflicts between threads
                open_ports.append((port, service))  # store port and service together as a pair
                print(f"Port {port}: OPEN  -->  {service.upper()}")

    except socket.error:
        pass # Skips port that errors out

def save_results(host, start_port, end_port):
    # Get the current date and time to timestamp the scan
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a filename based on the target and time so each scan has a unique file
    filename = f"scan_{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # Open the file and write the results to it
    # 'w' means write mode — creates the file if it doesn't exist
    with open(filename, "w") as f:
        f.write(f"Port Scan Results\n")
        f.write(f"=================\n")
        f.write(f"Target:     {host}\n")
        f.write(f"Port Range: {start_port} - {end_port}\n")
        f.write(f"Scanned At: {timestamp}\n")
        f.write(f"=================\n\n")
        
        if open_ports:
            for port, service in sorted(open_ports):  # unpack each port/service pair
                f.write(f"Port {port}: OPEN  -->  {service.upper()}\n")
        else:
            f.write("No open ports found.\n")
    
    print(f"\nResults saved to {filename}")

# Loops through a range of ports and scans each one
def scan(host, start_port, end_port):
    print(f"Scanning {host} from port {start_port} to {end_port}...\n")

    threads = [] # This list keeps track of all our threads

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port))
        threads.append(thread) 
        thread.start()  

    for thread in threads: 
        thread.join()

    print(f"\nScan complete!")
    print(f"\n{'Port':<10} {'Service'}")
    print(f"{'-'*20}")

    # Print a clean table of results sorted by port number
    for port, service in sorted(open_ports):
        print(f"{port:<10} {service.upper()}")

     # Ask the user if they want to save the results
    save = input("\nSave results to file? (y/n): ")
    if save.lower() == "y":
        save_results(host, start_port, end_port)

# Main program starts here ---
# Ask the user to type in the target (IP address or hostname like "localhost")
target = input("Enter the target IP or hostname: ")
start = int(input("Enter the start port: "))
end = int(input("Enter the end port: "))

scan(target, start, end)