import csv
from datetime import datetime, timedelta
from os import path
from time import sleep

import pynetbox
from elasticsearch import Elasticsearch, NotFoundError

ELK_USER = ''
ELK_PASS = ''
ELK_URL = ''
IPAM_TOKEN = ""
IPAM_URL = ''


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


def make_date(hours: float):
    times = int(float(hours) * 24)
    ranges = []
    for _range in range(times + 1):
        time_to = datetime.now() - timedelta(minutes=15*_range)  # - timedelta(hours=3)
        time_at = time_to - timedelta(minutes=15)
        ranges.append([time_at.strftime('%Y-%m-%dT%H:%M:00.000Z'), time_to.strftime('%Y-%m-%dT%H:%M:00.000Z')])
    return ranges


def get_body(_range):
    body = {
        "aggs": {
            "2": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "30s",
                    "time_zone": "UTC",
                    "min_doc_count": 1
                }
            }
        },
        "stored_fields": [
            "*"
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
                        "range": {
                            "@timestamp": {
                                "gte": f"{_range[0]}",
                                "lte": f"{_range[1]}",
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
    return body


@try_repeat
def get_unique_ips(time_range, keys=None):
    es = connect_elk(quiet=True)
    body = get_body(time_range)
    try:
        data = es.search(index='logstash*', body=body, size=10000, request_timeout=30)
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)

    hits = data['hits']['hits']
    count = 0
    for hit in hits:
        ip = None

        date_gross = hit['_source']['@timestamp'].split('.')[0]
        date = datetime.strptime(date_gross, '%Y-%m-%dT%H:%M:%S')
        try:
            ip = hit['_source']['user_address']
        except Exception as e:
            print('ERROR IP: ', e)
            continue
        flag = False
        for num in range(150, 161):
            continetn_ip = f'10.{num}.'
            if continetn_ip in ip:
                flag = True
                break
        if ip in keys or ip is None or flag:
            continue
        keys.append(ip)
        count += 1

    es.close()
    print(f"{count} ip адресов добавлено!")
    sleep(0.3)
    return keys


# PART 2. SEARCH NAT >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

def make_date_for_stack(delta):
    today = datetime.now() - timedelta(days=delta - 1)
    yesterday = datetime.now() - timedelta(days=delta)
    return today.strftime('%Y-%m-%dT21:00:00.000Z'), yesterday.strftime('%Y-%m-%dT20:59:59.000Z')


def get_stack_body(stack, delta):
    day_to, day_from = make_date_for_stack(delta)
    should = []
    for ip in stack:
        should.append({"match_phrase": {"user_address": f"{ip}"}})
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
                    "time_zone": "UTC",
                    "min_doc_count": 1
                }
            }
        },
        "stored_fields": [
            "*"
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
                        "bool": {
                            "should": should,
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
                "must_not": [
                    {
                        "match_phrase": {
                            "user_agent": "Drupal Command"
                        }
                    }
                ]
            }
        },
    }

    return body


def get_stack_data(body, dict_ips, es):

    try:
        data = es.search(index='logstash*', body=body, size=10000, request_timeout=40)
        print('Connected! ')
    except Exception as e:
        raise Exception(e)
    hits = data['hits']['hits']
    count = 0
    for hit in hits:
        ip = name = agent = date = None
        ip = hit['_source']['user_address']
        try:
            name = hit['_source']['user_name']
        except:
            pass
        agent = hit['_source']['user_agent']
        date_gross = hit['_source']['@timestamp'].split('.')[0]
        date = datetime.strptime(date_gross, '%Y-%m-%dT%H:%M:%S')
        if ip not in dict_ips.keys():
            dict_ips[ip] = [[str(date), name, agent]]
        else:
            dict_ips[ip].append([str(date), name, agent])
        count += 1
    sleep(0.3)
    return dict_ips


def search_nat(stack: list, days: int):
    es = connect_elk(quiet=True)
    full_data = {}
    for day in range(1, int(days) + 1):
        body = get_stack_body(stack, day)
        full_data = get_stack_data(body, full_data, es)
    es.close()
    return full_data


def get_info(ips, days):
    ips.sort()
    last_index = 0
    big_data = {}
    for i in range(0, len(ips), 50):
        if i == 0:
            continue
        stack = []
        for j in range(last_index, i):
            stack.append(ips[j])
            last_index = j
        data = search_nat(stack, days)
        big_data.update(data)
    return big_data


def get_tenant_by_ip(ip):
    nb = connect_ipam()
    tenant = None
    _ip = nb.ipam.ip_addresses.get(address=ip)
    if _ip:
        return str(_ip.tenant)
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
    sleep(0.3)
    return tenant

