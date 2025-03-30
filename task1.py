import os
import re
import socket
import subprocess
import requests
from ipaddress import ip_address, IPv4Address


def is_valid_ip(address):
    try:
        return bool(ip_address(address))
    except ValueError:
        return False


def get_asn_info(ip):
    if not is_valid_ip(ip) or ip_address(ip).is_private:
        return None, None, None

    try:
        url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        asn = None
        country = None
        provider = None

        for record in data.get('data', {}).get('records', []):
            for attr in record:
                key = attr.get('key', '').lower()
                value = attr.get('value', '')

                if key == 'origin' and not asn:
                    asn = value.split()[0]
                elif key == 'country' and not country:
                    country = value
                elif key in ['netname', 'descr'] and not provider:
                    provider = value

        if not asn:
            url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
            response = requests.get(url, timeout=5)
            data = response.json()
            asn = data.get('data', {}).get('asns', [None])[0]
        return asn, country, provider

    except Exception as e:
        print(f"Error when receiving information for {ip}: {str(e)}")
        return None, None, None


def trace_route(target):
    try:
        if not is_valid_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                print(f"Failed to resolve domain name: {target}")
                return []

        command = ['tracert', '-d', target]

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()
        output = output.decode('cp866', errors='ignore')

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ip_list = []

        for line in output.split('\n'):
            if '***' in line:
                break

            match = ip_pattern.search(line)
            if match:
                ip = match.group()
                if ip not in ip_list and ip != target:
                    ip_list.append(ip)

        return ip_list
    except Exception as e:
        print(f"Error when tracing: {e}")
        return []


def main():
    target = input("Enter the domain name or IP address for tracing: ")
    ip_list = trace_route(target)

    print("| № | IP | AS | Country | Provider |")

    for i, ip in enumerate(ip_list, 1):
        if ip_address(ip).is_private:
            print(f"| {i} | {ip} | N/A (private IP) | N/A | N/A |")
            continue

        asn, country, provider = get_asn_info(ip)

        asn_display = f"AS{asn}" if asn else "N/A"
        country_display = country if country else "N/A"
        provider_display = provider if provider else "N/A"

        print(f"| {i} | {ip} | {asn_display} | {country_display} | {provider_display} |")


if __name__ == "__main__":
    main()