FROM ubuntu:16.04
MAINTAINER Alexander Kutelev <alexander@kutelev.ru>
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python3-pytest python3-requests
ADD *.py /root/workdir/
WORKDIR "/root/workdir"
ENTRYPOINT ["py.test-3", "-v", "spider.py"]
