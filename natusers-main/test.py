import csv
import json
import time
from colorama import Fore, Style
from ping3 import ping
import nmap3

from utils import get_tenant_by_ip


def portscan(ip):
    nmap = nmap3.Nmap()
    results = nmap.scan_top_ports(ip, default=500, args=('-Pn'))
    target_ports = ['22', '80', '8080', '443']
    nat = True
    print('*' * 50)
    print(ip)
    for port in results[ip]['ports']:
        # if port['portid'] in target_ports:
        if port['state'] == 'open':
            print(port)
            # print(f"IP: {ip}, PORT: {port['portid']}, STATE: {port['state']}, SERVICE_NAME: {port['service']['name']}")
            # nat = True

    return nat


def scanning(ips):
    start_time = time.time()
    to_del = []
    to_scan = []
    count = 0
    for ip in ips:
        res = ping(ip, timeout=1)
        if res is not None:
            print(ip, '- is UP')
            count += 1
            to_scan.append(ip)
        else:
            to_del.append(ip)

    print(count, 'HOSTS is UP')

    for ip in to_scan:
        count += 1
        if not(portscan(ip)):
            to_del.append(ip)
    print(count, 'Всего просканированно!')
    print(Fore.BLUE + "Scan of ports Ended in:" + Style.RESET_ALL,
          Fore.GREEN + str(round(time.time() - start_time)) + Style.RESET_ALL, "s")

    return


if __name__ == '__main__':
    ips = []
    with open('ips.txt') as f:
        reader = f.readlines()
        for row in reader:
            ips.append(row.replace('range = ', '').replace('\n', ''))
    scanning(ips[:10])


