#!/bin/bash

device=eth0

dev_rule=$(tc qdisc show dev $device)

if [[ "$dev_rule" == "" ]]; then
  tc qdisc add dev $device root tbf rate 1000Mbit latency 0.1ms burst 500000
else
  tc qdisc replace dev $device root tbf rate 1000Mbit latency 0.1ms burst 500000
fi
