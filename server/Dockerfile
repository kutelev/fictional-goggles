FROM ubuntu:16.04
MAINTAINER Alexander Kutelev <alexander@kutelev.ru>
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python3-pip python3-pymongo mongodb
# bottle version which comes with Ubuntu 16.04 has a critical (for us) issue. Installing newer version using pip.
RUN pip3 install --upgrade pip
RUN pip3 install bottle
RUN mkdir -p /data/db
ADD *.py /root/workdir/
ADD *.sh /root/workdir/
WORKDIR "/root/workdir"
ENTRYPOINT ["bash", "start.sh"]
