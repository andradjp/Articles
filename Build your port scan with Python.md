# Build your port scanner with built-in libraries in Python

This small article will show, how you can build a port scanner with built-in libraries in Python and without need to 
install external libraries.

Many times when we're performs a troubleshooting or a pentest, we need check if there's connectivity between two hosts. 
Normally in this process we using tools such as: nmap, NetCat, Telnet, Hping3 e etc. Company's that has a security policy 
performs a process called **"Hardening"**. It's process consist in remove all unnecessary tools for the purpose of the server.

The script show here will help you in this task, hence if you are perform a pentest generate less noise. It will perform 
a scan type Full Connection, therefore the three handshake will complete. More later in other article, I'll show how we
 can perform a Stealth Scan, Xmas Scan and others.

Below, I list all libraries use in this script.

- <a href="https://docs.python.org/3.8/library/socket.html">socket</a>
- <a href="https://docs.python.org/3.8/library/sys.html">sys</a>
- <a href="https://docs.python.org/3.8/library/errno.html">errno</a>
- <a href="https://docs.python.org/3.8/library/os.html">os</a>
- <a href="https://docs.python.org/3.8/library/argparse.html">argparse</a>
- <a href="https://docs.python.org/3.8/library/ipaddress.html">ipaddress</a>

The version of Python that was use: **3.8.1**

Let's get started!

## Main Class

    import sys
    import errno
    import os
    import argparse
    import ipaddress
    
    class MyPortScanner(object):
    
        def __init__(self, target, portlist):
        self.target = target
        if type(portlist) is str:
            self.portlist = [int(x) for x in portlist.split(',')]
        else:
            self.portlist = portlist

In this first part, we just import the necessary libraries and define the class constructor. It'll receive two parameters: 
target IP and ports. If the user set a port list separeted per comma, we'll generate a list of integers with this port list.

## Function for check ports

    def check_port_socket_v4_tcp(self):
    
            print('--------------------------------')
            print('[+] Initializing scan...')
            print('[i] Target host: {}'.format(self.target))
            print('[i] Ports: {}'.format(self.portlist))
    
            try:
                for port in self.portlist:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    result = s.connect_ex((str(self.target), port))
    
                if result == 0:
                    print('[+] Port {}: Open'.format(port))
                else:
                    print('[!] Port {}: Closed'.format(port))
                    print('\t[-] Code error: {}'.format(errno.errorcode[result]))
                    print('\t[-] Message: {}'.format(os.strerror(result)))
                s.close()
            except socket.error as e:
                print(str(e))
                print('[-] Connection Error')
            sys.exit()
            print('[+] Script finished.')

Here our script begins be built. We define the function called "check_port_socket_v4_tcp" that wait a parameter: the 
class's instance. After this some informations are showed and begins a loop for test all ports in our list **portlist.** 
In next line we create a object of class socket with belows parameters: AF_INET == IPv4 and SOCK_STREAM == TCP. After 
this we set a timeout for 3 seconds and finally we tested the port and save the result for test in the result variable.

Lastly we verify the result, if the result is 0 then the port is **Open**, else is block for any other reasons.

## Testing the script

    joaopaulo@Joaos-MacBook-Air scanner % python3 sample_port_scanner.py -t 54.207.20.104 -p 80,443,445
    --------------------------------
    [+] Initializing scan...
    [i] Target host: 54.207.20.104
    [i] Ports: [80, 443, 445]
    [+] Port 80: Open
    [+] Port 443: Open
    [!] Port 445: Closed
            [-] Code error: EAGAIN
            [-] Message: Resource temporarily unavailable
    [+] Script finished.

For test your script, open a CLI session and set 2 parameters: -t for define the target and -p (not required) to define
 the ports scanned. Below a example: **python3 sample_port_scanner.py -t 54.207.20.104 -p 80,443,445**
 
## Complete Code

    # Import modules
    import socket
    import sys
    import errno
    import os
    import argparse
    import ipaddress

    # Main Class
    class MyPortScanner(object):
    
        # Constructor, receive two parameters: target = IP that will be scanned and list of port that will be tested
        def __init__(self, target, portlist):
            self.target = target
            if type(portlist) is str:
                self.portlist = [int(x) for x in portlist.split(',')]
            else:
                self.portlist = portlist
    
        # Function that performs the scan on v4 family
        def check_port_socket_v4_tcp(self):
    
            print('--------------------------------')
            print('[+] Initializing scan...')
            print('[i] Target host: {}'.format(self.target))
            print('[i] Ports: {}'.format(self.portlist))
    
            try:
                for port in self.portlist:
                    # Create the v4 socket, AF_INET == V4 Family, SOCK_STREAM == TCP
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # Define the timeout of response to 3 seconds
                    s.settimeout(3)
                    result = s.connect_ex((str(self.target), port))
                    # If the return code is 0 then the port is OPEN
                    if result == 0:
                        print('[+] Port {}: Open'.format(port))
                    # Otherwise, the port is closed
                    else:
                        print('[!] Port {}: Closed'.format(port))
                        print('\t[-] Code error: {}'.format(errno.errorcode[result]))
                        print('\t[-] Message: {}'.format(os.strerror(result)))
                    s.close()
            # If have any problem with connection, the scan will be aborted
            except socket.error as e:
                print(str(e))
                print('[-] Connection Error')
                sys.exit()
    
            print('[+] Script finished.')
    
    
    # Performs the script
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='Scan ports TCP\nVersion: 0.1')
        # Target parameter, accept just IPV4 Address
        parser.add_argument('-t', dest='target_host_v4', help='Target host IPv4', required=True, type=ipaddress.IPv4Address)
        # Port that will be scanned, if this parameter not been set then the default ports will be scanned
        parser.add_argument('-p', dest='ports', help='Ports separated by comma', type=str, default=[21, 22, 23, 53, 80, 443,
                                                                                                    3389, 389, 3306, 1521,
                                                                                                    8080, 8000])
        params = parser.parse_args()
        # Create an instance of MyPortScanner
        m = MyPortScanner(params.target_host_v4, params.ports)
        # Call the function check_port_socket_v4_tcp
        m.check_port_socket_v4_tcp()

Author: Joao Paulo Andrade

Data: 16/02/202

Web Site: www.jpandrade.info

Download of the code on GitHub: <a href="https://github.com/andradjp/hacktools/blob/master/scanner/sample_port_scanner.py">GitHub</a>

For any questions, send me a email <a href="mailto:contact@jpandrade.info">here</a>
