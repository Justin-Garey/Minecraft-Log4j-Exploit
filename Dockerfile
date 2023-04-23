# syntax = docker/dockerfile:1.3

FROM ubuntu:14.04

WORKDIR /server

COPY ./server /server

RUN sudo mkdir -p /usr/lib/jvm

RUN tar -zxvf jre-8u181-linux-x64.tar.gz -C /usr/lib/jvm

RUN sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jre1.8.0_181/bin/java" 1

CMD chmod +x start_server.sh && ./start_server.sh

EXPOSE 25565