FROM ubuntu:16.04
MAINTAINER Alexander Kutelev <alexander@kutelev.ru>
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python3-pip python3-pymongo python3-requests mongodb nginx
# bottle version which comes with Ubuntu 16.04 has a critical (for us) issue. Installing newer version using pip.
RUN pip3 install --upgrade pip
RUN pip3 install bottle
RUN mkdir -p /data/db
RUN rm /etc/nginx/sites-enabled/default
ADD fictional-goggles.conf /etc/nginx/sites-enabled/fictional-goggles.conf
RUN sed -i 's!^\(\s*access_log\)[^;]*;!\1 /dev/fd/1;!' /etc/nginx/nginx.conf
RUN sed -i 's!^\(\s*error_log\)[^;]*;!\1 /dev/fd/2;!' /etc/nginx/nginx.conf
ADD *.py /root/workdir/
ADD *.sh /root/workdir/
ADD *.html /root/workdir/
WORKDIR "/root/workdir"
ENTRYPOINT ["bash", "start.sh"]
