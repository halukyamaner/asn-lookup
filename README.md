# ASN Lookup

## Overview
ASN Lookup is a Python library that resolves IP addresses and performs Autonomous System Number (ASN) lookups. Utilizing RDAP and WHOIS, this library provides detailed information about network allocation, country codes, and other relevant data. It is ideal for cybersecurity assessments, network analysis, and educational purposes in network management.

## Features
- **Domain and IP Resolution**: Automatically resolves domain names to IP addresses and validates IP inputs.
- **Detailed ASN Lookups**: Leverages RDAP and WHOIS to fetch extensive details about the ASN and its associated network.
- **Error Handling**: Gracefully manages errors, offering clear feedback on input validation and lookup failures.

## Requirements
- Python 3.x
- `ipwhois` module (version 1.2.0 or higher)

## Usage
To perform an ASN lookup, simply provide an IP address or a domain name. The library will handle the resolution of the domain to an IP, if necessary, and then carry out the ASN lookup.

```bash
python ip_asn_lookup_script.py
