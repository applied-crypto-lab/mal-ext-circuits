#!/bin/bash

for ((i = 1; i <= 3; i++))
do
	openssl genrsa -out private-$i.pem 2048
	openssl rsa -in private-$i.pem -outform PEM -pubout -out public-$i.pem
done

