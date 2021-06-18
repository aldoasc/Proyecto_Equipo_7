#!/bin/bash

[[ -f "$1" ]] || { echo "se esperaba como primer parametro un archivo env"; exit 1; }

for linea in $(ccdecrypt -c "$1"); do
	export $linea
done

python manage.py runserver 0.0.0.0:8080
