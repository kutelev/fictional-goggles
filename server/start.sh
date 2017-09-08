mongod > /dev/null 2>&1 &
sleep 10 # Just in case
python3 rest_server.py
