import json
import csv
from copy import copy
from datetime import datetime, timedelta
from time import sleep
import os
from os import path

import pynetbox
from elasticsearch import Elasticsearch, NotFoundError

from settings import *


def try_repeat(func):
    def wrapper(*args, **kwargs):
        count = 3
        while count:
            try:
                return func(*args, **kwargs)
            except NotFoundError:
                count = 0
                print('Сервер перегружен, попробуйте позже!')
            except Exception as e:
                print(e)
                print('ReConnect...')
                count -= 1
    return wrapper


def make_date(time_range):
    if time_range == 1:
        delta = 0
    else:
        delta = 1 * (time_range - 1)
    to_day = datetime.now() - timedelta(days=delta)
    from_day = to_day - timedelta(days=1)

    return to_day.strftime('%Y-%m-%dT21:00:00.000Z'), from_day.strftime('%Y-%m-%dT20:59:59.000Z')


def connect_elk():
    user = ELK_USER
    pssw = ELK_PASS
    url = ELK_URL

    es = Elasticsearch(
        [url],
        http_auth=(user, pssw),
        scheme='http',
        timeout=20
    )
    print('Connecting to ELK...')
    return es


def connect_ipam():
    token = IPAM_TOKEN
    url = IPAM_URL
    print('Connecting to ipsm.mchs.ru')

    nb = pynetbox.api(
        url,
        token=token,
        threading=True,
    )
    return nb


def get_body(delta):
    day_to, day_from = make_date(delta)
    body = {
      "sort": [
        {
          "@timestamp": {
            "order": "desc",
            "unmapped_type": "boolean"
          }
        }
      ],
      "aggs": {
        "2": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "3h",
            "time_zone": "Europe/Moscow",
            "min_doc_count": 1
          }
        }
      },
      "stored_fields": [
        "*"
      ],
      "script_fields": {},
      "docvalue_fields": [
        {
          "field": "@timestamp",
          "format": "date_time"
        }
      ],
      "_source": {
        "excludes": []
      },
      "query": {
        "bool": {
          "must": [],
          "filter": [
            {
              "match_all": {}
            },
            {
              "match_phrase": {
                "sd.event.etdn": "Статус устройства \\\"Критический\\\"."
              }
            },
            {
              "range": {
                "@timestamp": {
                  "gte": f"{day_from}",
                  "lte": f"{day_to}",
                  "format": "strict_date_optional_time"
                }
              }
            }
          ],
          "should": [],
          "must_not": [
            {
              "match_phrase": {
                "sd.event.etdn": "Обнаружена сетевая атака"
              }
            }
          ]
        }
      },
    }
    return body, day_to


def make_human_date(string: str):
    date = string.split('.')[0]
    _date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
    date = datetime.strftime(_date, '%Y-%m-%d %H:%M')
    return date


def get_body_sed_exist(ip):
    day_to, day_from = make_date(14)
    body = {
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "boolean"
                }
            }
        ],
        "aggs": {
            "2": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "30m",
                    "time_zone": "Europe/Moscow",
                    "min_doc_count": 1
                }
            }
        },
        "stored_fields": [
            "*"
        ],
        "script_fields": {
            "user_logon_only": {
                "script": {
                    "source": "if (doc.containsKey('winlog.event_data.TargetUserName.keyword') && !doc['winlog.event_data.TargetUserName.keyword'].empty) {\n    if (doc['winlog.event_data.TargetUserName.keyword'].value =~ /^.*\\$$/) {\n        return false;\n    } else {\n        return true;\n    }\n}\nreturn false;",
                    "lang": "painless"
                }
            },
            "region_url": {
                "script": {
                    "source": "if (doc.containsKey('region.keyword') && !doc['region.keyword'].empty) {\n    def region_value = doc['region.keyword'].value;    \n    return region_value;\n}\ndef region_value = '#';    \nreturn region_value;",
                    "lang": "painless"
                }
            },
            "winlog_event_data_ipaddress_url": {
                "script": {
                    "source": "if (doc.containsKey('winlog.event_data.IpAddress.keyword') && !doc['winlog.event_data.IpAddress.keyword'].empty) {\n    def ip_value = doc['winlog.event_data.IpAddress.keyword'].value;\n    return ip_value;\n}\ndef region_value = '-';    \nreturn region_value;",
                    "lang": "painless"
                }
            }
        },
        "docvalue_fields": [
            {
                "field": "@timestamp",
                "format": "date_time"
            },
            {
                "field": "docker.time",
                "format": "date_time"
            },
            {
                "field": "event.created",
                "format": "date_time"
            },
            {
                "field": "nextcloud.time",
                "format": "date_time"
            },
            {
                "field": "nginx.time_iso8601",
                "format": "date_time"
            },
            {
                "field": "snoopy.date_iso_8601",
                "format": "date_time"
            },
            {
                "field": "winlog.event_data.NewTime",
                "format": "date_time"
            },
            {
                "field": "winlog.event_data.PreviousTime",
                "format": "date_time"
            }
        ],
        "_source": {
            "excludes": []
        },
        "query": {
            "bool": {
                "must": [],
                "filter": [
                    {
                        "match_all": {}
                    },
                    {
                        "exists": {
                            "field": "user_address"
                        }
                    },
                    {
                        "match_phrase": {
                            "user_address": f"{ip}"
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"{day_from}",
                                "lte": f"{day_to}",
                                "format": "strict_date_optional_time"
                            }
                        }
                    }
                ],
                "should": [],
                "must_not": [
                    {
                        "match_phrase": {
                            "user_agent": "Drupal Command"
                        }
                    }
                ]
            }
        }
    }
    return body, day_to


@try_repeat
def run_search(delta, hosts, file=None):
    es = connect_elk()
    body, day = get_body(delta)
    from_date = day[:10]
    if not hosts:
        hosts = set()
    try:
        data = es.search(index='kasper*', body=body, size=10000, request_timeout=40)
        print('Connected! ')
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)
    print()
    hits = data['hits']['hits']
    arr = []
    for hit in hits:
        ip = '-'
        source = hit['_source']
        date = source['@timestamp'].split('.')[0]
        _date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
        date = datetime.strftime(_date, '%Y-%m-%d %H:%M')
        region = source['region']
        p1 = str(source['sd']['event']['p1'])
        hostname = p1.split("'")[1]
        if hostname in hosts:
            continue
        event = p1.split(':')[1].strip()
        if 'Защита выключена' in event or 'Давно не выполнялся поиск вирусов' in event \
                or 'Серверы KSN недоступны' in event or 'Обнаружен' in event or 'Программа безопасности' in event\
                or 'стало неуправляемым' in event:
            hosts.add(hostname)
            arr.append([date, region, hostname, ip, event])
    es.close()
    if file:
        if path.isfile(file):
            with open(f'./{file}', 'a+', newline='') as f:
                wr = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
                wr.writerows(arr)
        else:
            with open(f'./{file}', 'w', newline='') as f:
                fieldnames = ["дата", "регион", "hostname", "IP", "уведомление"]
                wr = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
                wr.writerow(fieldnames)
                wr.writerows(arr)
    print('Return at...')
    sleep(1)
    print(f'{from_date} done!')
    sleep(1)
    return arr, hosts


def get_ips_from_ipam(file: str):
    output = file.split('.')[0] + '_update.csv'
    nb = connect_ipam()
    new_arr = []
    fieldnames = None
    with open(file) as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        ip = None
        count = 0
        for row in reader:
            q = nb.dcim.devices.filter(q=row['hostname'])
            if q:
                for item in q:
                    try:
                        row['IP'] = str(item.primary_ip).split('/')[0]
                    except:
                        row['IP'] = None
                    try:
                        row['регион'] = str(item.tenant.name)
                    except:
                        row['регион'] = None
                    new_row = list(row.values())
                    new_arr.append(new_row)
                    print(new_row)
                    break
            else:
                count += 1
                print(count, 'Нет в IPAM:', row['hostname'])

    with open(output, 'w', newline='') as f1:
        wr = csv.writer(f1, delimiter=';', quoting=csv.QUOTE_ALL)
        wr.writerow(fieldnames)
        wr.writerows(new_arr)
    return new_arr, output


@try_repeat
def search_sed_exist(ip, es):
    body, day = get_body_sed_exist(ip)
    from_date = day[:10]
    try:
        data = es.search(index='logstash*', body=body, size=10000, request_timeout=40)
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)
    if data['hits']['hits']:
        hits = data['hits']['hits']
        length = len(hits)
        for hit in hits:
            length -= 1
            date_connect = make_human_date(hit['_source']['@timestamp'])
            name = org = None
            try:
                name = hit['_source']['user_name']
                if name == '' and name is not None:
                    try:
                        name = hit['_source']['user_fio']
                    except:
                        pass
            except:
                pass
            try:
                org = hit['_source']['user_org']
            except:
                pass
            return date_connect, name, org

    else:
        return False, False, False


def find_sed_enter(file):
    for_output = []
    fileObject = csv.reader(open(file))
    row_count = sum(1 for row in fileObject)
    row_count -= 1
    with open(file) as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        es = connect_elk()
        for row in reader:
            row_count -= 1
            if row['IP'] is None:
                continue
            date_connect, name, org = search_sed_exist(row['IP'], es)
            if date_connect:
                new_row = copy(row)
                new_row['Был доступ к СЭД'] = date_connect
                new_row['Имя сотрудника'] = name if name else '-'
                new_row['Организация/отдел'] = org if org else '-'
                for_output.append(list(new_row.values()))
                print('Осталось ', row_count, " строк")
            else:
                continue
    with open(f'./kasper_ip_in_sed.csv', 'w', newline='') as f:
        fieldnames = ["дата", "регион", "hostname", "IP", "уведомление",
                      "Дата и время последнего входа в СЭД", 'Имя сотрудника', 'Организация/отдел']
        wr = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
        wr.writerow(fieldnames)
        wr.writerows(for_output)


def get_tenant_by_ip(ip):
    nb = connect_ipam()
    tenant = ' '
    pref = nb.ipam.prefixes.filter(q=ip)
    try:
        tenant = pref._response_cache[0]['tenant']['name']
    except:
        pass
    if tenant is None:
        try:
            tenant = pref.response.gi_frame.f_locals['i']['tenant']['name']
        except:
            print()
    return tenant


def get_data_from_ipam(ip, nb):
    tenant = None
    region = None
    prefix = None
    aggregate = None
    tenant_id = None
    try:
        q = nb.ipam.ip_addresses.get(address=ip)
        try:
            prefix = nb.ipam.prefixes.get(q=ip)
        except:
            prefixes = nb.ipam.prefixes.filter(q=ip)
            for item in prefixes:
                prefix = item
                tenant = prefix.tenant
                break
        aggregate = nb.ipam.aggregates.get(q=prefix.prefix)
        if tenant is None:
            try:
                tenant = nb.tenancy.tenants.get(name=q.tenant)
            except:
                try:
                    tenant_name = None
                    for attr in aggregate:
                        if tenant_name is not None:
                            break
                        if 'tenant' in attr:
                            tenant_name = aggregate.tenant.name
                            break
                        else:
                            for attr in prefix:
                                if 'tenant' in attr:
                                    tenant_name = prefix.tenant.name
                                    break
                    tenant = nb.tenancy.tenants.get(name=tenant_name)
                except:
                    pass
    except:
        aggregate = nb.ipam.aggregates.get(q=ip)
        q = None
    if q is None:
        res = {
            'ip': ip,
            'prefix': prefix if prefix is not None else 'нет в IPAM',
            'aggregate': aggregate if aggregate is not None else 'нет в IPAM',
            'tenant': tenant if tenant is not None else 'нет в IPAM',
            'tenant_id': tenant.id if tenant is not None else 'нет в IPAM',
        }
    else:
        try:
            id = tenant.id
        except:
            id = '-'
        res = {
            'ip': ip,
            'prefix': prefix,
            'aggregate': aggregate,
            'tenant': tenant,
            'tenant_id': id
        }
    return res


def get_unique_ip_from_csv(ip_ipam_arr, file=None, ip_arr=None):
    nb = connect_ipam()
    count = 0
    unique_ips = []
    if file:
        with open(file) as f:
            reader = csv.reader(f, delimiter=';')
            for row in reader:
                ip = row[1]
                if ip in ip_ipam_arr.keys() or '10.151.' in str(ip) or '10.155.' in str(ip):
                    # print("Not unique")
                    continue
                else:
                    res = get_data_from_ipam(ip, nb)
                    # tenant = get_tenant_by_ip(ip)
                    row.append(res['tenant'])
                    row.append(res['tenant_id'])
                    row[2], row[3], row[4], row[5] = row[4], row[5], row[2], row[3]
                    unique_ips.append(row)
                    count += 1
                    print(count, row)
    elif ip_arr:
        for row in ip_arr:
            ip = row[1]
            if ip in ip_ipam_arr.keys():
                print("Not unique")
                continue
            else:
                res = get_data_from_ipam(ip, nb)
                # tenant = get_tenant_by_ip(ip)
                row.append(res['tenant'])
                row.append(res['tenant_id'])
                row[2], row[3], row[4], row[5] = row[4], row[5], row[2], row[3]
                unique_ips.append(row)
                count += 1
                print(count, row)

    with open('unique1.csv', 'w', newline='') as f1:
        wr = csv.writer(f1, delimiter=';', quoting=csv.QUOTE_ALL)
        wr.writerows(unique_ips)

    return unique_ips


def check_in_ipam(arr, file=None):
    nb = connect_ipam()
    ips = []
    q = nb.ipam.ip_addresses.all()
    print('Этот процесс может занять несколько минут...')
    for item in q:
        ips.append(str(item.address).split('/')[0])
    output = open('unique_result.csv', 'w')
    writer = csv.writer(output)
    if file:
        input = open(file, 'r')
        for row in csv.reader(input):
            ip = row[1]
            if ip in ips or '10.151.' in ip[:7]:
                print(ip, 'Есть в IPAM!')
            else:
                writer.writerow(row)
    else:
        for row in arr:
            ip = row[1]
            if ip in ips or '10.151.' in ip[:7]:
                print(ip, 'Есть в IPAM!')
            else:
                writer.writerow(row)
    return




