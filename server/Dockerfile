FROM ubuntu:16.04
MAINTAINER Alexander Kutelev <alexander@kutelev.ru>
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python3-pip python3-pymongo mongodb git
# bottle version which comes with Ubuntu 16.04 has a critical (for us) issue. Installing newer version using pip.
RUN pip3 install --upgrade pip
RUN pip3 install bottle
