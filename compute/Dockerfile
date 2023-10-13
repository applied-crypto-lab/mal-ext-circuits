FROM ubuntu:20.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git gcc g++ libcrypto++-dev libssl-dev libgmp-dev libgmp10 libssl1.1 bison flex make iproute2

RUN git clone https://github.com/applied-crypto-lab/mal-ext-circuits

RUN chmod 700 /mal-ext-circuits/build.sh
RUN chmod 700 /mal-ext-circuits/compute/LAN.sh
RUN chmod 700 /mal-ext-circuits/compute/run-comp.sh

WORKDIR "/mal-ext-circuits"

RUN ./build.sh

WORKDIR "/mal-ext-circuits/compute"