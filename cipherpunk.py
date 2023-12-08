import ssl
import socket
import sys
import requests

#Checks if certificate is valid
def verify_ssl_certificate(hostname, port):
    #print('Testing Certificate....')
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                #print("Certificate is valid.")
                return 'valid'
    except ssl.SSLError:
        return ''

#This function lists the ciphers that are supported by both client and server
def list_ssl_ciphers(hostname, port):
    #print('Testing Ciphers....')
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                ciphers = ssock.shared_ciphers()
                #print(ciphers)
        return ciphers
    except ssl.SSLError:
        return ''

#Returns the version of ssl/tls
def test_port_ssl(hostname, port):
    #print('Testing port for TLS/SSL....')
    r = requests.get("https://" + hostname, verify=False)
    raw_version = str(r.raw.version)
    version = raw_version[0] + '.' + raw_version[1]
    return version
    
#Determines if a port is open value 0 indicates an open port
def find_open_port(hostname, port):
    #print('Testing port if open/closed........')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = 1
    try:
        result = sock.connect_ex((hostname, port))
        if result == 0:
            print('Port {}: OPEN'.format(port))
        sock.close()
    except socket.error:
        print('Could not connect to server')
        sys.exit()
    except KeyboardInterrupt:
        print('Exiting...')
        sys.exit()
    return result

#return the ip address of a hostname
def get_host_ip(hostname):
    #print('Getting host ip address....')
    return socket.gethostbyname(hostname)

#return the hostname from an ip address
def get_host_name(ip):
    #print('Getting host name.....')
    return socket.getfqdn(ip)

w1 = "www.w3schools.com"
w2 = "www.cybersecsyndicate.com"
w3 = "www.example.com"
host_list = [w1, w2, w3]
results = []
for host in host_list:
    open_ports = []
    #if target is IP address get hostname
    if host[0].isnumeric():
        name = get_host_name(host)
        ip_addr = host
    #if target is a hostname get ip address
    elif host[0].isnumeric()==False:
        name = get_host_name(host)
        ip_addr = get_host_ip(name)

    #Sample test port list
    port_list = [80, 443, 8080, 8888]
    for port in port_list:
        host_dict = {'target': host, 'hostname': name, 'ip_addr': ip_addr, 'open_port': '', 'ssl_ports': '', 'ssl_ciphers': [], 'cert': ''}
        #Test if port is open/closed
        port_status = find_open_port(name, port)
        if port_status == 0:
            host_dict['open_port']=port
            #Test if port is an SSL port
            port_protocol = test_port_ssl(host_dict['hostname'], port)
            is_ssl = False
            if port_protocol[0].isnumeric():
                is_ssl=True
                host_dict['ssl_ports']=port
            #Determine if certificate is valid and list ciphers
            if is_ssl:
                host_dict['cert']=verify_ssl_certificate(host_dict['hostname'], port)
                host_dict['ssl_ciphers'].append(list_ssl_ciphers(host, port))
                print(host_dict)
        else:
            continue
