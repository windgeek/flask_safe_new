ps aux|grep /data/python3.9/bin/gunicorn|grep -v grep|awk '{print $2}'|xargs kill