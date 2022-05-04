from datetime import datetime

from utils import run_search, get_ips_from_ipam, find_sed_enter


def main(days, filename):
    hosts_arr = set()
    ip_arr = None
    for day in range(1, days+1):
        if ip_arr:
            res, hosts = run_search(day, hosts_arr, file=file_name)
            ip_arr += res
            hosts_arr.update(set(hosts))
        else:
            ip_arr, hosts = run_search(day, hosts_arr, file=filename)
            hosts_arr.update(set(hosts))
    return ip_arr


if __name__ == '__main__':
    today = datetime.strftime(datetime.now(), '%Y-%m-%d')
    file_name = f'kas_critical_{today}.csv'
    events = main(7, file_name)
    arr, out_file = get_ips_from_ipam(file_name)
    # out_file = 'kas_critical_2022-01-19_update.csv'
    find_sed_enter(out_file)
    print()

