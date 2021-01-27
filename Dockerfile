#FROM maven:3.6-openjdk-8-slim
#
##COPY . /protect
#WORKDIR /protect
#
##RUN mvn clean && \
##    mvn install -DskipTests

#FROM ubuntu:18.04
#
#RUN apt-get -y update
#
#RUN apt-get install -y --force-yes --no-install-recommends openjdk-8-jdk-headless maven
#
#RUN apt-get install -y --force-yes iproute2 iputils-ping curl openssh-client
#
#WORKDIR /protect
