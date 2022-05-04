import sqlite3
import datetime
import logging


conn = sqlite3.connect('my_db.db', check_same_thread=False)
cursor = conn.cursor()
date = datetime.datetime.today()
month = date.strftime('%B %Y')


def create_table(table):
    cursor.execute(f"""CREATE TABLE {table}
                   (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                   ip TEXT NOT NULL,
                   tenant TEXT NOT NULL,
                   date_create TEXT NOT NULL)"""
                   )
    print(f'table {table} created!')


def drop_table(table):
    cursor.execute(f"""DROP TABLE {table}""")
    print(f'table {table} removed!')


def get_ips(table):
    statement = f"SELECT ip, tenant FROM {table}"
    cursor.execute(statement)
    result = cursor.fetchall()
    return result


def add_ip(ip, tenant, table):
    today = datetime.datetime.today()
    date = today.strftime('%d-%m-%Y')
    statement = f"INSERT INTO {table} (ip, tenant, date_create) VALUES ('{ip}', '{tenant}','{date}')"
    cursor.execute(statement)
    conn.commit()


def add_many_ips(records, table):
    statement = f"INSERT INTO {table} (ip, tenant, date_create) VALUES (?, ?, ?)"
    cursor.executemany(statement, records)
    conn.commit()


# if __name__ == "__main__":
#     table = 'ip_addresses'
#     drop_table(table)
#     create_table(table)



