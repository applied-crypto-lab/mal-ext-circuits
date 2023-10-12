#!/bin/bash

tc qdisc replace dev eth0 root tbf rate 1000Mbit latency 0.1ms burst 500000