import socket # socket is a built-in Python library that lets us make network connections

# Checks if a single port is open on the target host
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"Port {port}: OPEN")
    except socket.error:
        print("Could not connect to host")

# Loops through a range of ports and scans each one
def scan(host, start_port, end_port):
    print(f"Scanning {host} from port {start_port} to {end_port}...\n")
    for port in range(start_port, end_port + 1):
        scan_port(host, port)
    print("\nScan complete!")

# Ask the user to type in the target (IP address or hostname like "localhost")
target = input("Enter the target IP or hostname: ")
start = int(input("Enter the start port: "))
end = int(input("Enter the end port: "))

scan(target, start, end)