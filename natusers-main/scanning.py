import csv
import datetime
import json
import time
from colorama import Fore, Style
from ping3 import ping
import nmap3

from utils import get_tenant_by_ip


def portscan(ip):
    nmap = nmap3.Nmap()
    results = nmap.scan_top_ports(ip, default=1000, args=('-Pn'))
    target_ports = ['22', '80', '8080', '443']
    nat = False
    for port in results[ip]['ports']:
        if port['portid'] in target_ports:
            print(f"IP: {ip}, PORT: {port['portid']}, STATE: {port['state']}, SERVICE_NAME: {port['service']['name']}")
            nat = True
    print('*'*50)
    return nat


def scanning(filename):
    f = json.load(open(filename))
    start_time = time.time()
    to_del = []
    count = 0
    for ip in f.keys():
        res = ping(ip, timeout=3)
        if res is not None:
            print(ip, '- is UP')
            count += 1
        else:
            to_del.append(ip)

    print(count, 'HOSTS is UP')
    for ip in to_del:
        del f[ip]
    to_del = []
    for ip in f.keys():
        if not(portscan(ip)):
            to_del.append(ip)
    for ip in to_del:
        del f[ip]
    print(Fore.BLUE + "Scan of ports Ended in:" + Style.RESET_ALL,
          Fore.GREEN + str(round(time.time() - start_time)) + Style.RESET_ALL, "s")

    today = datetime.datetime.now().strftime('%Y-%m-%d')
    with open(f'report{today}.csv', 'w', newline='') as csvfile:
        fieldnames = ['ip', 'date', 'user_name', 'user_agent', 'tenant']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for k, v in f.items():
            last_user = ''
            last_agent = ''
            tenant = get_tenant_by_ip(k)
            print(tenant)
            for row in v:
                if row[1] == last_user and row[2] == last_agent:
                    continue
                else:
                    last_user, last_agent = row[1], row[2]
                    writer.writerow({"ip": k, 'date': row[0], 'user_name': row[1], 'user_agent': row[2], 'tenant': tenant})
    return


if __name__ == '__main__':
    file_json = 'nat_ips.json'
    scanning(file_json)

