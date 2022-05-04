#!/bin/bash

cd "$(dirname "$0")"

if [ -n "$1" ]
then
  echo
  echo "Обновляем IP адреса 8\)"
  echo "Your argumet is - $1."
  echo "Now, i don\`t need any arguments, please try again without arguments and from the root folder"
  echo
else
  COMMAND="python3 ./main.py --elk -d 7"
  echo "Выгрузка Доступ без МИ за 7 дней 8\)"
  eval $COMMAND || {
    echo "--------------------------------------------------------------------"
    echo "Шо то не получилось :( "
    echo "--------------------------------------------------------------------"
    }
  echo
  echo "Успешно!"
fi
