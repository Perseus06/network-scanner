"""
Written by perseus06

Name:
network_scanner.py

Description:
This script can be used for mapping all endpoints in the LAN, including an OS detection of the endpoints (similar to the Nmap tool).
The script can map the network by making either a ping sweep (using ARP and ICMP packets), or using the ARP table data saved on the host. The OS detection is made by analyzing the TTL value in the IP header.
Pay attention that the script is adapted to windows OS only.
"""

# imports
import scapy.all as scapy
import subprocess as sub
import re

# constants
MAIN_MESSAGE = """Hello!
for detecting the endpoints in the LAN and their OS, you will need to:
1. run this program from CMD only!
2. choose method for scanning the network.

There are two methods - using ping sweep or the arp table.
On the one hand - ping sweep allows you to find all the endpoints in the LAN for sure, but is very noisy and can be detected.
On the other hand - arp table might miss few endpoints in the LAN, but much harder to detect because it is a very quiet method.

The choice is in your hands - do you prefer performence or quiet?
For choosing the ping sweep (performence), enter '1'.
For choosing the arp table (quiet), enter '2'.\n\n"""
REGEX_PATTERN_FOR_NETWORK_DETAILS = r"IPv4 Address[. ]+: ([\d.]+)\s+Subnet Mask[. ]+: ([\d.]+)\s+Default Gateway[ .]+: .+\s+([\d.]+)"


# ===== general functions =========
# getting self IP address, the subnet mask of the network and the default gateway of the network (IP of the LAN's interface in the router).
def get_network_details():
    # run the ipconfig command and save its output.
    ipconfig = sub.check_output("ipconfig", shell=True).decode('latin1')
    # using regex for extracting the necessary info from the ipconfig command.
    necessary_data = re.search(REGEX_PATTERN_FOR_NETWORK_DETAILS, ipconfig)
    self_ip = necessary_data.group(1)
    subnet_mask = necessary_data.group(2)
    default_gateway = necessary_data.group(3)
    # return tuple of the network details.
    network_info = (self_ip, subnet_mask, default_gateway)
    return network_info


# function for getting a network ID of an IP based on the subnet mask in the LAN.
def get_netID(ip):
    # split each octat in the subnet mask and in the IP.
    sm_list = subnet_mask.split(".")
    ip_list = ip.split(".")
    netID_list = []
    # based on the subnet mask, extract from the IP the network ID only.
    for i in range(len(sm_list)):
        if sm_list[i]!="0":
            netID_list.append(ip_list[i])
    netID = ".".join(netID_list)
    return netID
  

# function for detecting the os of the endpoint by the ICMP response's ttl.
def detect_os_via_ttl(ttl):
    if ttl<=64:
        output = "os: linux/macOS"
    elif 65<=ttl<=128:
        output = "os: windows"
    elif 129<=ttl<=255:
        output = "os: network device"
    else:
        output = "os: could not be detected"
    return output


# ========= ping sweep functions ========
# function for mapping all ip addresses in the LAN using ping sweep (works only when subnet mask is 255.255.255.0).
def ping_sweep_mapping():
    print("scanning the network, takes some time...")
    final = ""
    # iterate over each possible IP address in the LAN.
    for i in range(1,255):
        # form the IP of the current endpoint in the iteration, by connecting the network ID and the current host ID (i).
        endpoint_ip = "{}.{}".format(netID, i)
        # send ARP request to the endpoint in order to get it's MAC address.
        answer = scapy.sr(scapy.ARP(pdst=endpoint_ip), timeout=0.1, verbose=False)[0]
        # from the answer received, get the MAC address of the destination.
        for sent, received in answer:
            endpoint_mac = received.hwsrc
        # if the destination MAC is valid (17 chars long), then send an ICMP request
        if len(endpoint_mac)==17:
            # form and send the ICMP request to the destination IP.
            icmp_req_packet = scapy.Ether(dst=endpoint_mac)/scapy.IP(dst=endpoint_ip)/scapy.ICMP()
            answer = scapy.srp(icmp_req_packet, timeout=0.1, verbose=False)[0]
            # add to the final string the data found about the current destination IP, based on the ARP and ICMP packets sent.
            for sent, received in answer:
                ttl = received.ttl
                final += f"ip: {endpoint_ip}\nmac: {endpoint_mac}\n"
                # add the TTL analysis returned by detect_os_via_ttl() function.
                final += detect_os_via_ttl(ttl)
                final += "\n\n\n"
        endpoint_mac="0"
    # in the end, print the final string with the data about all the endpoints found in the network.
    print(f"\n\n\n\n{final}")
        

# ======== arp table functions ========
# function for filtering our ip and broadcast ip from the ip addresses list.
def filter_endpoints(endpoints_list):
    for ep in endpoints_list:
        ip = ep[0]
        # if the IP of the current endpoint is our IP (self IP) or the broadcast IP, remove the endpoint from the list.
        if ip==self_ip:
            endpoints_list.remove(ep)
        elif ip==f"{netID}.255":
            endpoints_list.remove(ep)


# function for mapping all ip addresses (or at least some of them) in the LAN using the arp table in our endpoint.
def arp_table_mapping():
    # execute the arp -a command and split the output by lines (each line is value in the list).
    output = sub.check_output("arp -a", shell=True).decode().split("\r\n")
    
    # removing uneccessery data from the cmd output.
    output = output[3:-1]
    endpoints_list = []
    # iterate over each line in the arp -a output (every line contain data of specific endpoint in the LAN).
    for line in output:
        # no error should raise in case the current line truly contain endpoint data, so the try-except filters .
        try:
            # get the IP, MAC and net ID of the current endpoint from the ARP table.
            endpoint= re.split(r"\s+", line)
            endpoint_ip = endpoint[1]
            endpoint_mac = endpoint[2].replace("-", ":")
            endpoint_net_id = get_netID(endpoint_ip)
            # making sure the current endpoint truly has the same net ID as ours. if not, this IP does not relevant for the program.
            if endpoint_net_id == netID:
                endpoints_list.append((endpoint_ip, endpoint_mac))
        except:
            None
            
    # filter endpoints from the list using filter_endpoints() function.
    filter_endpoints(endpoints_list)
    print("\n\n\n\n\n")
    # iterate over each endpoint in the endpoints list.
    for endpoint in endpoints_list:
        endpoint_ip = endpoint[0]
        endpoint_mac = endpoint[1]
        # form and send an ICMP request packet to the endpoint.
        packet = scapy.Ether(dst=endpoint_mac)/scapy.IP(dst=endpoint_ip)/scapy.ICMP()
        output = scapy.srp(packet, timeout=1, verbose=False)[0]
        # analyze the TTL from the ICMP response returned by the endpoint, and print all the endpoint's details.
        for sent, received in output:
            print(f"ip: {endpoint_ip}\nmac: {endpoint_mac}")
            packet_ttl = received.ttl
            print(detect_os_via_ttl(packet_ttl), end="\n\n\n")


def main():
    # get general details on the network and save them as global variables.
    global self_ip, subnet_mask, default_gateway, netID
    self_ip, subnet_mask, default_gateway = get_network_details()
    netID = get_netID(self_ip)
    # print the main message of the program and receive as input the method chosen by the user.
    print(MAIN_MESSAGE)
    choice = input("Enter your choice ('1' or '2'): ")
    # the program will keep asking for input as long the user will insert wrong input.
    while choice!="1" and choice!="2":
        print("WRONG INPUT!!!")
        choice = input("Enter your choice ('1' or '2'): ")
    # if the user chose the ping sweep option.
    if choice =="1":
        # check the subnet mask for avoiding a ping sweep over too large LAN.
        if subnet_mask=="255.255.255.0":
            ping_sweep_mapping()
        else:
            print("LAN is too big for using a ping sweep, must use arp table instead.")
            arp_table_mapping()
    # if the user chose the ARP table option.
    elif choice=="2":
        arp_table_mapping()
        

if __name__=="__main__":
    main()
