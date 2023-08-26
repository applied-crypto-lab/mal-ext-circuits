#!/bin/bash

sudo tc qdisc del dev ens3 root
sudo tc qdisc add dev ens3 root tbf rate 1000Mbit latency 0.1ms burst 500000
sudo tc qdisc show dev ens3
