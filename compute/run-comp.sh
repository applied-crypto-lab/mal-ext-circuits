#!/bin/bash

circuit_type=$1	#in {arith, bit}
threat_model=$2 #in {sh, mal}
chosen_alg=$3	#in {add, mul, lt, equ, ed, all}, choice of "all" subject to circuit_type, threat_model
cfg=$4			#user chosen based on file name: runtime-config-$cfg
peer_id=$5		#in {0, 1, 2, 3}, if peer_id == 0, then the picco seed program is run
debug_flag=$6	#in {debug, single}, optional

num_iters=2
secparam=48
net_config_file="runtime-config-$cfg"
keyfile="private-$peer_id.pem"

Algs=("add" "mul" "lt" "equ" "ed")
num_algs=${#Algs[@]}
Bitlens=()

notify_and_quit()
{
	echo
	echo $1
	echo
	exit
}

if { ! [[ "$circuit_type" == "arith" || "$circuit_type" == "bit" ]]; }; then
	notify_and_quit "Invalid circuit type"
fi

if { ! [[ "$threat_model" == "sh" || "$threat_model" == "mal" ]]; }; then
	notify_and_quit "Invalid threat model"
fi

if { ! { [[ ${Algs[@]} =~ $chosen_alg ]] || [[ "$chosen_alg" == "all" ]]; }; }; then
	notify_and_quit "Invalid algorithm"
fi

if (( $peer_id < 0 )) || (( $peer_id > 3 )); then
	notify_and_quit "Invalid peer id"
fi


set_max()
{
	if (( $2 > $3 )); then
		eval $1=$2
	else
		eval $1=$3
	fi
}

set_field_len()
{
	if [[ "$circuit_type" == "bit" ]]; then
		field_len=3
	elif [[ "$circuit_type" == "arith" ]]; then
		field_len=32
		if [[ "${Algs[$1]}" == "lt" || "${Algs[$1]}" == "equ" || "${Algs[$1]}" == "ed" ]]; then
			field_len=$((field_len + secparam))
		fi
	fi
	if [[ "$threat_model" == "mal" ]]; then
		set_max field_len $field_len $secparam
	fi
	Bitlens[${alg}]="$field_len"
}

for ((alg = 0; alg < $num_algs; alg++));
do
	set_field_len $alg
done


if [[ "$debug_flag" == "debug" ]]; then
	Input_Size=(1 10 100)
	Input_Rep=(1 1 1)
	num_iters=1
elif [[ "$circuit_type" == "bit" ]]; then
	Input_Size=(1 10 100 1000)
	Input_Rep=(1000 1000 1000 100)
elif [[ "$circuit_type" == "arith" ]]; then
	Input_Size=(1 10 100 1000 10000 100000)
	Input_Rep=(1000 1000 1000 100 100 50)
fi

num_input_dims=${#Input_Size[@]}

if [[ "$debug_flag" == "single" ]]; then
	for ((size = 0; size < num_input_dims; size++))
	do
		Input_Rep[$size]=1
	done
	num_iters=1
fi

executable="./${circuit_type}_${threat_model}"
Sleeptime=(8 4 2 0)

params="$peer_id $net_config_file $keyfile 1 1 fakeinput out"

for ((this_alg = 0; this_alg < $num_algs; this_alg++))
do
	rep_ctr=$(($num_iters * $num_input_dims))
	for ((this_size = 0; this_size < $num_input_dims; this_size++))
	do
		for ((iter = 0; iter < $num_iters; iter++))
		do
			if [[ "$chosen_alg" == "${Algs[$this_alg]}" || "$chosen_alg" == "all" ]]; then
				if [[ "$peer_id" == "0" ]]; then
					#run picco seed program
					param_config_file="u_${Bitlens[${this_alg}]}"
					cmd="../compiler/bin/picco-seed ${net_config_file} ${param_config_file}"
					echo "COMMAND: $cmd"
					eval "$cmd"
					while (( $rep_ctr > 0 ))
					do
						if [ -a "flag.txt" ];
						then
							eval "rm flag.txt"
							rep_ctr=$((rep_ctr - 1))
							sleep 1
							echo "COMMAND: $cmd"
							eval "$cmd"
						else
							echo "sleep"
							sleep 10
						fi
					done
				else
					#run computational party
					cmd="$executable $params ${Input_Size[$this_size]} ${Input_Rep[$this_size]} ${Algs[$this_alg]} $debug_flag"
					echo "COMMAND: $cmd"
					eval $cmd
					sleep ${Sleeptime[$peer_id]}
					if [ "$peer_id" = 1 ]; then
						touch flag.txt
					fi
				fi
			fi
		done
	done
done




