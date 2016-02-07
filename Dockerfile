# ElasticPotPY Dockerfile by MS
#
# VERSION 16.03.2
FROM ubuntu:14.04.3
MAINTAINER MS

# Setup apt
RUN apt-get update -y && apt-get upgrade -y

# Install packages
RUN apt-get install -y python3 pip3 python3-setuptools supervisor git
RUN easy_install3 bottle requests simpleconfigparser
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10

# Setup user, groups and configs
RUN addgroup --gid 2000 tpot && \
    adduser --system --no-create-home --shell /bin/bash --uid 2000 --disabled-password --disabled-login --gid 2000 tpot

#ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set workdir and start glastopf
#WORKDIR /data/elasticpot/
#CMD ["/usr/bin/supervisord"]