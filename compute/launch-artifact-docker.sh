#!/bin/bash

###############################################################################
# Efficiently Compiling Secure Computation Protocols From Passive to
# Active Security: Beyond Arithmetic Circuits
#	Copyright (C) 2024  Marina Blanton and Dennis Murphy,
# University at Buffalo, State University of New York.
#
#	This program is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program.  If not, see <https://www.gnu.org/licenses/>.
###############################################################################

cfg_file=runtime-config-$1
peer_id=$2
net_device=$3

notify_and_quit()
{
	echo
	echo $1
	echo
	exit
}

if [[ "$cfg_file" == "" ]]; then
  notify_and_quit "Missing config file suffix"
fi

if [ "$peer_id" == "0" ]; then
  eval "docker exec -it mal-ext-circuits-1 /bin/bash"
  exit
fi

if [[ -e results/ ]]; then
  rm -rf results/*
fi

if ! [[ $peer_id =~ ^[0-3]+$ ]]; then
	notify_and_quit "Invalid peer id \"$peer_id\"; must be between 0 and 3 inclusive"
fi

if ! [[ -e $cfg_file ]]; then
  notify_and_quit "Could not find config file $cfg_file"
fi

Config_Lines=()
while IFS= read -r line
do
  Config_Lines+=("$line")
done < "$cfg_file"

for line in ${Config_Lines[@]}; do
  Line_Splits=()
  IFS=',' read -ra Line_Splits <<< "$line"
  if [[ "${Line_Splits[0]}" == "$peer_id" ]]; then
    port_num=${Line_Splits[2]}
  fi
done

container_name="mal-ext-circuits-$peer_id"

eval "docker run -it --rm --network="host" -p $port_num:$port_num --cap-add=NET_ADMIN --detach --name $container_name mal-ext-circuits-image /bin/bash"

if [[ "$cfg_file" == "runtime-config-local" ]]; then
  eval "docker exec -it $container_name /mal-ext-circuits/compute/LAN.sh $net_device"
else
  eval "docker cp $cfg_file $container_name:/mal-ext-circuits/compute"
fi

eval "docker exec -it $container_name /bin/bash"
eval "docker exec -it $container_name /bin/bash -c \"mkdir -p /results; cp -f *_test_results* /results\""

if ! [[ -e results/ ]]; then
  mkdir results
fi

eval "docker cp $container_name:/results/. results/"
eval "docker stop $container_name"

if [[ -e results/time_test_results_1.csv ]] && [[ -e results/time_test_results_2.csv ]] && [[ -e results/time_test_results_3.csv ]]; then
  echo "Compiling timing data"
  eval "python3 extract_time_results.py results/"
fi


