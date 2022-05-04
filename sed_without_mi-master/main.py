import argparse
import csv
import datetime
import os
import time
from os import path
import multiprocessing
import threading

from db_manage import drop_table, create_table, get_ips
from utils import run_search, get_ips_from_ipam, get_unique_ip_from_csv, check_in_ipam, get_uniq_ips, make_report, \
    run_search_nat
"""
Комадна для вызова скрипта включает в себя аргументы, которые можно комбинировать.
"-d 5" За сколько дней получить выгрузку. Комбинируется со всеми кроме "--db" Данный ключь обязателен для всех выгрузок, кроме обновления БД IP адресов из IPAM
'--db' - Выгрузить актуальную информацию из IPAM в собственную базу. Можно комбинировать со всеми другими ключами.
'--elk' - Выгрузка уникальных пользователей заходивших в СЭД без установленного МИ. Комбинируется только с днями
'--savz' - Выгрузка уникальных пользователей заходивших в СЭД без установленного АВЗ. Комбинируется только с днями
'--mac'  - Выгрузка уникальных пользователей заходивших в СЭД с ОС MAC. Комбинируется только с днями
'--nat'  - Выгрузка уникальных пользователей заходивших в СЭД из сети NAT. Комбинируется только с днями
"""
parser = argparse.ArgumentParser(description="Unique SED IPs script")
parser.add_argument('--elk', help='get date fron elk', action="store_true")
parser.add_argument('-d', '--days', help='days to get')
parser.add_argument('--db', help='update database', action="store_true")
parser.add_argument('--savz', help='get users without SAVZ', action="store_true")
parser.add_argument('--mac', help='MAC OS only', action="store_true")
parser.add_argument('--nat', help='NAT users in SED', action="store_true")

args = parser.parse_args()


def run(days, ips_from_elk=None, savz=None, mac=False):
    ips = set()
    ip_arr = None
    if ips_from_elk:
        for day in range(1, days + 1):
            if ips_from_elk:
                res = run_search(day, ips)
                ips_from_elk += res
            else:
                ips_from_elk = run_search(day, ips)
        return ips_from_elk
    elif savz:
        for day in range(1, days + 1):
            if ip_arr:
                res = run_search(day, ips)
                ip_arr += res
            else:
                ip_arr = run_search(day, ips)
                print(f'Day {days} DONE!')
        return ip_arr
    else:
        # NEW VERSION
        # pool = multiprocessing.Pool(processes=2)
        # ip_arr = run_search(1, ips)
        # pool.map(run_search, [(day, ips) for day in range(1, days + 1)])
        # NEW VERSION CLOSE
        for day in range(1, days + 1):
            if ip_arr:
                res = run_search(day, ips, file='./unique_elk.csv', mac=mac)
                if res is not None:
                    ip_arr += res
            else:
                ip_arr = run_search(day, ips, file='./unique_elk.csv', mac=mac)
        print(f'Day {days} DONE!')
        return ip_arr


def search_nat(days):
    ips = set()
    ip_arr = None
    file_name = 'nat_users.csv'
    for day in range(1, days + 1):
        if ip_arr:
            res = run_search_nat(day, ips, file_name)
            ip_arr += res
        else:
            ip_arr = run_search_nat(day, ips, file_name)
    return ip_arr


def main():
    timer = time.time()
    elk = args.elk
    days = int(args.days) if args.days else 1
    db = args.db
    savz = args.savz
    mac = args.mac
    nat = args.nat
    # elk = True
    # days = 1
    # db = False
    # savz = False
    # mac = False
    # nat = False

    table = 'ip_addresses'
    unique_ips_file = './unique.csv'
    if path.isfile('unique_elk.csv'):
        os.remove('unique_elk.csv')
    if path.isfile('unique1.csv'):
        os.remove('unique1.csv')
    ips_from_elk = None

    if elk and db:
        drop_table(table)
        create_table(table)
        ips_from_elk = None

        thread1 = multiprocessing.Process(target=get_ips_from_ipam)
        thread2 = multiprocessing.Process(target=run, args=(days, ips_from_elk))
        thread2.start()
        time.sleep(0.5)
        thread1.start()

        thread2.join()
        thread1.join()

    else:
        if elk or mac:
           ips_from_elk = run(days, mac=mac)
        if db:
            try:
                drop_table(table)
            except:
                pass
            create_table(table)
            get_ips_from_ipam()
        if savz:
            uniq_ips = run(days, savz=savz)
            ip_arr = []
            for row in uniq_ips:
                ip = row[1]
                ip_arr.append(ip)
            ips = []
            for ip in ip_arr:
                ip = get_uniq_ips(ip=ip)
                if ip and ip not in ips:
                    ips.append(ip)
            print(ips)
            make_report(ips)
            print('ГОТОВО!')
            return
        if nat:
            result = search_nat(days)
            with open('NAT_users_result.csv', 'w', newline='') as f1:
                wr = csv.writer(f1, delimiter=';', quoting=csv.QUOTE_ALL)
                wr.writerow(['Дата', 'IP адрес', 'Имя пользователя', 'Подразделение', 'Браузер'])
                wr.writerows(result)
            return

    print('Формирую CSV файл c IP адресами и Учреждениями...')
    _all = get_ips(table)
    ips_set = {}
    for ip in _all:
        ips_set[ip[0]] = ip[1]
    unique_ips = get_unique_ip_from_csv(ips_set, file='unique_elk.csv', ip_arr=ips_from_elk)
    print("Всего: ", len(unique_ips), " адрсесов")

    # CHECK IP IN IPAM
    print('Убираем лишние адреса из файла')
    arr = check_in_ipam(unique_ips)
    print(f'Done, time left: {(time.time() - timer)/60} minutes')


if __name__ == '__main__':
    from rich import print
    from rich import pretty
    pretty.install()
    from rich.panel import Panel
    print(Panel.fit("[bold yellow]SC SED USERS! это скрипт выгрузки отчета по IP адресам!", border_style="red"))
    main()


"""
from rich.progress import track

        for n in track(range(n), description="Processing..."):
            do_work(n)
"""
