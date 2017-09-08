mongod > /dev/null 2>&1 &
python3 initdb.py > /dev/null 2>&1
python3 rest_server.py > /dev/null 2>&1 &
python3 web_server.py > /dev/null 2>&1 &
nginx -g 'daemon off;'
