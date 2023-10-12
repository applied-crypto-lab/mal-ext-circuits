#!/bin/bash

cfg_file=runtime-config-$1
peer_id=$2

if [ "$peer_id" == "0" ]; then
  eval "docker exec -it mal-ext-circuits-1 /bin/bash"
  exit
fi

notify_and_quit()
{
	echo
	echo $1
	echo
	exit
}

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

eval "docker run -it --rm --network="host" -p $port_num:$port_num --cap-add=NET_ADMIN --detach --name $container_name mal-ext-circuits /bin/bash"
eval "docker cp $cfg_file $container_name:/mal-ext-circuits/compute "
eval "docker exec -it $container_name /bin/bash"
eval "docker stop $container_name"


