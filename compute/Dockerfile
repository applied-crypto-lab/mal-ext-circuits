FROM ubuntu:20.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git gcc g++ libcrypto++-dev libssl-dev libgmp-dev libgmp10 libssl1.1 bison flex make iproute2

RUN git clone https://github.com/applied-crypto-lab/mal-ext-circuits

WORKDIR "/mal-ext-circuits"

RUN ./build.sh

COPY LAN.sh /mal-ext-circuits/compute/LAN.sh

RUN chmod 700 /mal-ext-circuits/compute/LAN.sh

WORKDIR "/mal-ext-circuits/compute"

CMD LAN.sh