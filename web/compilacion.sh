#!/bin/bash
HOST="192.168.56.104"
USER="alumno"
PASS="alumno"
RUTA="/home/alumno/web"

gcc web.c -o web

VAR=$(expect -c "
spawn scp -r web $USER@$HOST:$RUTA 
match_max 100000
expect \"*Password:*\"
send -- \"$PASS\r\"
send -- \"\r\"
expect eof
")
echo "==============="
echo "$VAR"

