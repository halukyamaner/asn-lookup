"""
Library: ASN Lookup
Author: Haluk YAMANER
Email: haluk@halukyamaner.com
Web: https://www.halukyamaner.com
Version: 1.0

Description:
    ASN Lookup is a Python library designed to resolve IP addresses and perform Autonomous System Number (ASN)
    lookups using RDAP and WHOIS. This library handles both direct IP entries and domain name resolutions, then
    queries the IP's ASN details, providing insights into network allocation, country code, and more. It is suited
    for applications requiring IP network analysis, cybersecurity assessments, and educational purposes on network management.

Usage:
    To use ASN Lookup, simply provide an IP address or a domain name. The library will resolve the IP if a domain
    is provided and then proceed with the ASN lookup. Results include detailed network information, ASN details,
    and historical event data for the IP's ASN.

Requirements:
    Python 3.x
    ipwhois>=1.2.0

Features:
    - Resolves domain names to IP addresses and checks the validity of IP inputs.
    - Uses RDAP and WHOIS for detailed ASN lookup, capturing extensive details about the ASN and its associated network.
    - Handles errors gracefully, providing clear feedback on input validation and lookup failures.
    - Designed for use in command-line interfaces, with interactive prompts for user input.

Potential Use Cases:
    - Network security applications requiring detailed IP and network insights.
    - Educational tools for teaching network management and internet architecture.
    - Tools for cybersecurity professionals to analyze network ownership and event history.

Example:
    Below is a simple example of how to use the ASN Lookup library:

    ```python
    # This script assumes you have installed the required `ipwhois` library.
    # Run the script in your command-line interface.

    from ip_asn_lookup import asn_lookup, get_ip_from_input

    # Prompt for IP address or domain name
    user_input = input("Please enter an IP address or domain name for ASN lookup: ")
    ip_address, is_domain = get_ip_from_input(user_input)

    if ip_address:
        print(f"ASN Information for {ip_address}:")
        asn_info = asn_lookup(ip_address)
        # Output will include ASN details, network information, and event history
    ```
"""
import socket
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

def get_ip_from_input(user_input):
    """Resolve input to an IP address if it's a domain, or verify it's an IP."""
    try:
        # Check if it's a valid IP address
        socket.inet_aton(user_input)
        return user_input, False  # Return the IP as-is and flag as direct IP input
    except socket.error:
        # If not a valid IP, assume it's a domain and try to resolve it
        try:
            ip_address = socket.gethostbyname(user_input)
            return ip_address, True  # Return resolved IP and flag as domain input
        except socket.gaierror:
            print("Invalid input: neither a valid IP address nor a resolvable domain.")
            return None, None

def asn_lookup(ip):
    """Perform ASN lookup for a given IP."""
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(asn_methods=["whois"])
        return res
    except IPDefinedError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"ASN lookup failed: {e}")
    return None

if __name__ == "__main__":
    # Prompt the user for either an IP address or domain name
    user_input = input("Please enter an IP address or domain name for ASN lookup: ")

    # Get the IP address from the input (whether it's a domain or an IP)
    ip_address, is_domain = get_ip_from_input(user_input)

    if ip_address:
        if is_domain:
            print()
            print(f"IP address for {user_input} is {ip_address}")
            print()

        # Perform ASN lookup
        asn_info = asn_lookup(ip_address)

        if asn_info:
            print(f"ASN Information for {ip_address}:")
            print()
            print(f"ASN: {asn_info['asn']}")
            print(f"ASN CIDR: {asn_info['asn_cidr']}")
            print(f"ASN Country Code: {asn_info['asn_country_code']}")
            print(f"ASN Registry: {asn_info['asn_registry']}")
            print(f"ASN Description: {asn_info['asn_description']}")
            print(f"ASN Allocation Date: {asn_info['asn_date']}")
            
            # Additional Network Details
            network_info = asn_info.get('network', {})
            if network_info:
                print("\nNetwork Details:")
                print(f"Network Name: {network_info.get('name', 'N/A')}")
                print(f"Network Start IP: {network_info.get('start_address', 'N/A')}")
                print(f"Network End IP: {network_info.get('end_address', 'N/A')}")
                print(f"Network Country: {network_info.get('country', 'N/A')}")
                print(f"Network Type: {network_info.get('type', 'N/A')}")
                print(f"Network Description: {network_info.get('description', 'N/A')}")

            # Print Event information
            events = asn_info.get('events', [])
            if events:
                print("\nEvent History:")
                for event in events:
                    print(f"Event: {event.get('event_action', 'N/A')}, Date: {event.get('event_date', 'N/A')}")

    else:
        print("Could not perform ASN lookup due to invalid input.")
