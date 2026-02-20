import socket # socket is a built-in Python library that lets us make network connections
import threading # allows us to run multiple scans at the same time for faster results

open_ports = [] # This list will store the open ports we find

lock = threading.Lock() # A lock to prevent multiple threads from writing to the open_ports list at the same time

# Checks if a single port is open on the target host
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            with lock: # Lock the list before writing to it so threads don't clash
                open_ports.append(port)
                print(f"Port {port}: OPEN")

    except socket.error:
        pass # Skips port that errors out

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

    print(f"\nScan complete. Open ports: {sorted(open_ports)}")

# Main program starts here ---
# Ask the user to type in the target (IP address or hostname like "localhost")
target = input("Enter the target IP or hostname: ")
start = int(input("Enter the start port: "))
end = int(input("Enter the end port: "))

scan(target, start, end)