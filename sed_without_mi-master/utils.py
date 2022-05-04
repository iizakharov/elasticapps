import json
import csv
from datetime import datetime, timedelta, date
from time import sleep
import os
from os import path

import pynetbox
from elasticsearch import Elasticsearch, NotFoundError
from rich import print

from db_manage import create_table, add_ip, get_ips, drop_table, add_many_ips
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
                print('[bold magenta]ReConnect...[/bold magenta]')
                count -= 1
    return wrapper


def make_date(delta, savz=False):
    if savz:
        today = datetime.now()
        yesterday = datetime.now() - timedelta(days=delta)
    else:
        today = datetime.now() - timedelta(days=delta-1)
        yesterday = datetime.now() - timedelta(days=delta)

    return today.strftime('%Y-%m-%dT21:00:00.000Z'), yesterday.strftime('%Y-%m-%dT20:59:59.000Z')


def connect_elk(quiet=None):
    user = ELK_USER
    pssw = ELK_PASS
    url = ELK_URL

    es = Elasticsearch(
        [url],
        http_auth=(user, pssw),
        scheme='http',
        timeout=20
    )
    if not quiet:
        print('Connecting to ELK...')
    return es


def connect_ipam():
    token = IPAM_TOKEN
    url = IPAM_URL
    nb = pynetbox.api(
        url,
        token=token
    )
    return nb


def check_file_and_create(file, arr):
    if file and arr:
        if path.isfile(file):
            with open(f'./{file}', 'a+', newline='') as f:
                wr = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
                wr.writerows(arr)
        else:
            with open(f'./{file}', 'w', newline='') as f:
                wr = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
                wr.writerows(arr)


def new_parse_json(obj, gen=0, title=None):
    new_dict = {}
    for key, value in obj.items():
        if key == 'message':
            try:
                value = json.loads(json.dumps(value, ensure_ascii=False))
                value = json.loads(value)
            except:  # noqa: E722
                pass
        if not isinstance(value, dict):
            if '@timestamp' in key:
                new_dict['@timestamp'] = value
                continue
            if key in new_dict.keys():
                if title is not None:
                    new_dict[f'{title}_{key}'] = value
                else:
                    new_dict[key] = value
            else:
                if title is not None:
                    new_dict[f'{title}.{key}'] = value
                else:
                    new_dict[key] = value
        else:
            title = key
            gen += 1
            new_dict.update(new_parse_json(value, gen, title))

    return new_dict


def get_body(delta, macintosh=None):
    day_to, day_from = make_date(delta)
    body = {
      "aggs": {
        "2": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "30s",
            "time_zone": "Europe/Moscow",
            "min_doc_count": 1
          }
        }
      },
      "stored_fields": [
        "*"
      ],
      "script_fields": {},
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
    body_mac = {
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
        "script_fields": {},
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
                            "user_agent": "*Macintosh*"
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
                "must_not": []
            }
        }
    }
    if macintosh:
        return body_mac, day_to
    return body, day_to


def get_body_nat(delta):
    nat_ip = "10.10.208.249"
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
                    "time_zone": "UTC",
                    "min_doc_count": 1
                }
            }
        },
        "stored_fields": [
            "*"
        ],
        "script_fields": {},
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
                            "user_address": nat_ip
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
                "must_not": []
            }
        }
    }
    return body, day_to


def get_body_savz(ips):
    day_to, day_from = make_date(14, savz=True)
    ips_arr = []
    for row in ips:
        ip = row[1]
        ips_arr.append({"match_phrase": {"endpoint_ip1": f"{ip}"}})
    body_savz = {
       "aggs": {
        "2": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "12h",
            "time_zone": "UTC",
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
                "avz_install": "false"
              }
            },
            {
              "bool": {
                "should": ips_arr,
                "minimum_should_match": 1
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
          "must_not": []
        }
      }
    }
    return body_savz, day_to


def get_body_for_savz(ip):
    day_to, day_from = make_date(14, savz=True)
    body = {
      "aggs": {
        "2": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "12h",
            "time_zone": "UTC",
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
                      "avz_install": "false"
                  }
              },
              {
                  "match_phrase": {
                      "endpoint_ip1": f"{ip}"
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
          "must_not": []
        }
      }
    }
    return body, day_to


@try_repeat
def run_search_nat(delta, ips, file):
    es = connect_elk()
    body, day = get_body_nat(delta)
    try:
        data = es.search(index='logstash*', body=body, size=10000, request_timeout=40)
        print('Connected! ')
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)

    hits = data['hits']['hits']
    count = 0
    arr = []
    for hit in hits:
        ip = name = _os = org = date = None

        date_gross = hit['_source']['@timestamp'].split('.')[0]
        date = datetime.strptime(date_gross, '%Y-%m-%dT%H:%M:%S')

        try:
            ip = hit['_source']['user_address']
        except Exception as e:
            print('ERROR IP: ', e)
            continue
        ips.add(ip)
        try:
            _os = hit['_source']['user_agent']
        except Exception as e:
            print('ERROR USER AGENT: ', e)
            continue
        count += 1
        try:
            name = hit['_source']['user_fio']
        except:
            # print('Нет имени пользователя')
            continue
        try:
            org = hit['_source']['user_org']
        except:
            # print('Нет имени пользователя')
            continue
        arr.append([date, ip, name, org, _os])
    es.close()
    print(count)
    check_file_and_create(file, arr)

    print('Return at...')
    sleep(1)
    return arr


@try_repeat
def run_search(delta, ips, file=None, mac=False):
    es = connect_elk()
    if mac:
        body, day = get_body(delta, macintosh=True)
    else:
        body, day = get_body(delta)
    date = day[:10]
    try:
        data = es.search(index='logstash*', body=body, size=10000, request_timeout=40)
        print('Connected! ')
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)
    es.close()
    if mac:
        hits = data['hits']['hits']
        count = 0
        arr = []
        for hit in hits:
            ip = name = _os = None
            ip = hit['_source']['user_address']
            if ip in ips or '10.151.' in ip:
                continue
            if '10.156.' in ip:
                ip = str(ip).replace('10.156.', '10.155.')
            _os = hit['_source']['user_agent']
            ips.add(ip)
            count += 1
            name = hit['_source']['user_fio']
            arr.append([date, ip, name, _os])

    else:
        hits = data['hits']['hits']
        count = 0
        arr = []
        for hit in hits:
            ip = name = _os = None
            try:
                ip = hit['_source']['user_address']

            except Exception as e:
                print('ERROR IP: ', e)
                continue
            if ip == '' or ip in ips or '10.151.' in ip or '10.155.' in ip:
                continue
            ips.add(ip)
            try:
                _os = hit['_source']['user_agent']
                if '(Windows NT 6.1)' in _os or '(Windows NT 6.1; )' in _os or '(Windows NT 5.1' in _os \
                        or '(Windows NT 6.3)' in _os or 'Windows NT 6.1; rv:' in _os:
                    continue
            except Exception as e:
                print('ERROR USER AGENT: ', e)
                continue
            count += 1
            try:
                name = hit['_source']['user_fio']
            except:
                # print('Нет имени пользователя')
                continue
            arr.append([date, ip, name, _os])

    print(count)
    check_file_and_create('./unique_elk.csv', arr)

    print('Return at...')
    print(f'{date} done!')
    sleep(1)
    return arr


@try_repeat
def get_uniq_ips(es=None, ip=None, uniq_ips=None):
    if not es:
        es = connect_elk(quiet=True)
    if uniq_ips:
        body, day = get_body_savz(uniq_ips)
    else:
        body, day = get_body_for_savz(ip)
    try:
        data = es.search(index='osquery*', body=body, size=10000, request_timeout=10)
        # print('Connected! ')
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)
    if not data['hits']['hits']:
        return
    hits = data['hits']['hits']
    es.close()
    for hit in hits:
        ip = None
        try:
            ip = hit['_source']['endpoint_ip1']

        except Exception as e:
            print('ERROR IP: ', e)
            continue
        if ip == '' or '10.151.' in ip or '10.155.' in ip:
            return None
        return ip


def get_ips_from_ipam():
    table = 'ip_addresses'
    nb = connect_ipam()
    q = nb.ipam.ip_addresses.filter(vrf__id=1)
    count = 0
    records = []
    # print('Начинаю заполнять базу IP адресами...')
    today = datetime.today()
    date = today.strftime('%d-%m-%Y')
    from rich.progress import track
    for ip in track(q, description="[bold green]Заполняю базу IP адресами...[/bold green]"):
        try:
            tenant = str(ip.tenant)# .replace(' ', '_')
        except:
            tenant = 'Не привязан к IPAM'
        records.append((str(ip.address).split('/')[0], tenant, date))
        # add_ip(str(ip.address).split('/')[0], tenant, table)
        count += 1
        if count % 5000 == 0:
            print(f' +  [bold green]{count}[/bold green]')
    print(f' +  [bold green]Добавляем в БД[/bold green]')
    add_many_ips(records, table)
    print('Всего добавлено: ', count)
    return


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
            from rich.console import Console
            console = Console()
            with console.status('[bold green]Выполняю задачи ... [/bold green]') as status:
                for row in reader:
                    ip = row[1]
                    if ip in ip_ipam_arr.keys() or ip in unique_ips or '10.151.' in str(ip) or '10.155.' in str(ip):
                        continue
                    res = get_data_from_ipam(ip, nb)
                    # tenant = get_tenant_by_ip(ip)
                    row.append(res['tenant'])
                    row.append(res['tenant_id'])
                    row[2], row[3], row[4], row[5] = row[4], row[5], row[2], row[3]
                    unique_ips.append(row)
                    count += 1
                    # print(count, row)
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


def make_report(ips):
    nb = connect_ipam()
    count = 0
    unique_ips = []
    with open('unique_elk.csv') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            ip = row[1]
            if ip in unique_ips or '10.151.' in str(ip) or '10.155.' in str(ip):
                continue
            if ip in ips:
                res = get_data_from_ipam(ip, nb)
                # tenant = get_tenant_by_ip(ip)
                row.append(res['tenant'])
                row.append(res['tenant_id'])
                row[2], row[3], row[4], row[5] = row[4], row[5], row[2], row[3]
                unique_ips.append(row)
                count += 1
                print(count, row)

    with open('ips_without_savz.csv', 'w', newline='') as f1:
        wr = csv.writer(f1, delimiter=';', quoting=csv.QUOTE_ALL)
        wr.writerows(unique_ips)


def check_in_ipam(arr, file=None):
    today = date.today().strftime('%Y_%m_%d')
    nb = connect_ipam()
    ips = []
    q = nb.ipam.ip_addresses.all()
    print('Этот процесс может занять несколько минут...')
    from rich.progress import track
    for item in track(q, description="[bold green]Заполняю базу IP адресами...[/bold green]"):
        ips.append(str(item.address).split('/')[0])
    output = open(f'unique_result{today}.csv', 'w')
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




