#!/bin/bash

net_device=$1

if [[ "$net_device" == "" ]]; then
  net_device=eth0
fi

dev_rule=$(tc qdisc show dev $net_device)

if [[ "$dev_rule" == "" ]]; then
  tc qdisc add dev $net_device root tbf rate 1000Mbit latency 0.1ms burst 500000
else
  tc qdisc replace dev $net_device root tbf rate 1000Mbit latency 0.1ms burst 500000
fi
