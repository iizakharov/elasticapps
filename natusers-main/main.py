import csv
import json
import subprocess
from datetime import datetime

from utils import make_date, get_unique_ips, get_info, get_tenant_by_ip
from scanning import scanning


def run(days):
    time_ranges = make_date(days)
    unique_ips = []
    length = len(time_ranges)
    for _range in time_ranges:
        unique_ips += get_unique_ips(_range, keys=unique_ips)
        unique_ips.sort()
        unique_ips = list(set(unique_ips))
        length -= 1
        print(f'Осталось {length} запросов в Elastic')
    with open('all_ips.txt', 'w') as file_txt:
        for ip in unique_ips:
            file_txt.write(f"{ip}\n")
    return unique_ips


def check_nat(data_file):
    nat_ips = {}
    for ip, values in data_file.items():
        count = 0
        last_agent = None
        for row in values:
            if last_agent is not None and last_agent[2] != row[2]:
                if count > 5:
                    if not(ip in nat_ips):
                        nat_ips.update({ip: values})
                        break
                count += 1

            last_agent = row
    today = datetime.now().strftime('%Y-%m-%d')
    with open(f"nat_ips{today}.json", "w", encoding="utf-8") as file:
        json.dump(nat_ips, file, ensure_ascii=False, indent=4)
    with open(f'nat_ips{today}.csv', 'w', newline='') as csvfile:
        fieldnames = ['ip', 'date', 'user_name', 'user_agent', 'tenant']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        res_file = json.load(open('nat_ips.json'))
        for k, v in res_file.items():
            tenant = get_tenant_by_ip(k)
            print(tenant)
            for row in v:
                writer.writerow({"ip": k, 'date': row[0], 'user_name': row[1], 'user_agent': row[2], 'tenant': tenant})
    return nat_ips


def main(days):
    # ШАГ 1 Получить все уникальные IP за период времени
    all_ips = run(days)
    print(len(all_ips))

    input('Шаг 1 окончен! Для продожения нажмите "ENTER" ')  # Пауза между шагами
    # ШАГ 2 Проверка каждого IP из шага 1 на наличие одновременных входнов в СЭД
    all_ips = [ip.replace('\n', '') for ip in open('all_ips.txt').readlines()]
    data = get_info(all_ips, days)
    with open("result1.json", "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

    input('Шаг 2 окончен! Для продожения нажмите "ENTER" ')  # Пауза между шагами
    # ШАГ 3 Тестирование шага 2
    data_file = json.load(open('result1.json'))
    check_nat(data_file)
    # input('Шаг 3 окончен! Для продожения нажмите "ENTER" ')  # Пауза между шагами
    # ШАГ 4 NMAP
    # scanning('nat_ips.json')


if __name__ == '__main__':
    main(1)
    # f = json.load(open('nat_ips.json'))
    # print(len(f.keys()))
    # process = subprocess.Popen(f'''nmap -sV 10.114.145.136 ''', shell=True)
