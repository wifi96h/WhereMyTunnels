#!/bin/bash
<<Comment

WhereMyTunnels.sh v0.3 written by Androsh7
https://github.com/Androsh7/WhereMyTunnels

MIT License

Copyright (c) 2024 Androsh7

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Comment

# Make me pretty:
# xterm -ah -title tunnel_monitor_v0.3.sh ./WhereMyTunnels.sh

# Screen file:
ssh_status="/tmp/ssh_status"

CYAN='\033[0;36m'
NC='\033[0m' # No Color

while [[ true ]]
do
	tunnel_pids=($(ss -ntlp | grep -Po "ssh\",pid=\d+,fd=5" | grep -Po "\d+," | cut -d',' -f1 | sort -u))
	socket_pids=($(ss -nap | grep "ssh\"" | grep -i "strLISTEN" | grep -Po "pid=\d+" | cut -d"=" -f2))	
	
	# all ssh sessions
	ssh_list=()
	ssh_sessions=$(ss -ntp | grep "ssh" | grep -Po "(\d{1,3}\.){3}\d{1,3}:\d+ .*pid=\d+" | sed -e 's/^/%/g')
	i=0
	z=2
	while [[ true ]]; do
		if [[ -z $(echo ${ssh_sessions} | cut -d"%" -f${z}) ]]; then
			break
		fi
		session=$(echo ${ssh_sessions} | cut -d"%" -f${z})
		src=$(echo ${session} | grep -Po "^[\d.]+:\d+")
		dst=$(echo ${session} | grep -Po " [\d.]+:\d+ ")
		pid=$(echo ${session} | grep -Po "pid=\d+" | cut -d"=" -f2)

		ssh_list[${i}]="${src} --> ${dst} - PID ${pid}"
		i=$[ $i + 1 ]
		z=$[ $z + 1 ]
	done

	
	# get traditional tunnels
	tunnel_list=()
	i=0
	for item in ${tunnel_pids[*]}; do
		process=$(ps -ef | grep -P "${item}" | grep -Po "ssh .*")
		ssh=$(echo $process | grep -Po "ssh (\w+@)?([a-zA-Z]\w+|[\d\.]+) (-p ?\d+)?")


		# formatting for source to dest port
		fwd_field=$(echo $process | grep -Po "\-[LR] ?\d+:([\d.]+|\w+):\d+" | cut -d" " -f2-)
		tunnel_list[${i}]=$(echo -e "${process} - PID ${item}")
		i=$[ $i + 1 ]
		# grab attached ssh session
		for ((x = 0 ; x < ${#ssh_list[@]} ; x++)); do
			if [[ $(echo ${ssh_list[${x}]} | grep -c "PID ${item}") -ge 1 ]]; then
				tunnel_list[${i}]="%SESSION: $(echo ${ssh_list[${x}]} | cut -d" " -f-3)"
				ssh_list[${x}]=""
			fi
		done

		if [[ -n $fwd_field ]]; then
			srcip="127.0.0.1"
			srcport=$(echo ${fwd_field} | cut -d":" -f1)
			dstip=$(echo ${fwd_field} | cut -d":" -f2)
			dstport=$(echo ${fwd_field} | cut -d":" -f3)
			
			tunnel_list[$[${i} + 1 ]]=$(echo -e "%${srcip}:${srcport} --> ${dstip}:${dstport}")
			i=$[ $i + 2 ]
		elif [[ -n $(echo $process | grep -Po "\-\w*D\w* ?9050") ]]; then
			tunnel_list[$[${i} + 1 ]]=$(echo -e "%FORWARD: 127.0.0.1:9050 --> DYNAMIC")
			i=$[ $i + 2 ]
		fi	
		fwd_field=""
	done

	# get master sockets and forwards
	socket_list=()
	i=0
	for item in ${socket_pids[*]}; do
		# get master socket command
		ms=$(ps -ef | grep -P "${item}" | grep -Po "ssh .*")
		socket_list[${i}]="$ms - PID ${item}"
		i=$[ $i + 1 ]
		
		# finds all local ports being forwarded via this master socket
		forward_ports=$(ss -ntlp | grep "pid=${item}" | grep -Po "127.0.0.1:\d+" | cut -d":" -f2 | sed -e 's/^/%/g')
		
		# grab attached ssh session
		for ((x = 0 ; x < ${#ssh_list[@]} ; x++)); do
			if [[ $(echo ${ssh_list[${x}]} | grep -c "PID ${item}") -ge 1 ]]; then
				socket_list[${i}]="%SESSION: $(echo ${ssh_list[${x}]} | cut -d" " -f-3)"
				ssh_list[${x}]=""
				i=$[ $i + 1 ]
			fi
		done
		# finds the master socket file
		socket_file=$(echo $ms | grep -Po '\-\w* [/\w]+' | cut -d" " -f2)
		#echo "file ${socket_file}"
		
		# iterates through all forward ports
		z=2 # counting var
		while [[ true ]]; do
			search_port=$(echo $forward_ports | cut -d"%" -f${z})
			
			# checks if there are no further ports to search for
			if [[ -z $search_port ]]; then
				break
			fi

			# grabs the port forward section of the command I.E: 1111:127.0.0.1:4444
			fwd_field=$(ps -ef | grep -Po "ssh .* -[LR] ?${search_port}?:.*" | grep -Po "\d+:.*")

			if [[ -n $fwd_field ]]; then
				srcip="127.0.0.1"
				srcport=$(echo ${fwd_field} | cut -d":" -f1)
				dstip=$(echo ${fwd_field} | cut -d":" -f2)
				dstport=$(echo ${fwd_field} | cut -d":" -f3)

				# output formatting
				socket_list[${i}]="%FORWARD: ${srcip}:${srcport} --> ${dstip}:${dstport}"

			elif [[ $search_port -eq 9050 ]]; then
				srcip="127.0.0.1"
				srcport="9050"
				
				# output formatting
                                socket_list[${i}]="%${srcip}:${srcport} --> DYNAMIC"
                                i=$[ $i + 1 ]
			else
				socket_list[${i}]="%FORWARD: 127.0.0.1:${search_port} --> UNK"
			fi
			i=$[ $i + 1 ]
			z=$[ $z + 1 ]
		done
	done
	
	# get non-tunnel ssh sessions	
	z=0
	nt_ssh_list=()
	for ((i = 0 ; i < ${#ssh_list[@]} ; i++)); do
		if [[ -z ${ssh_list[${i}]} ]]; then
			continue
		fi
		nt_ssh_list[${z}]=${ssh_list[${i}]}
		pid=$(echo ${ssh_list[${i}]} | grep -Po "PID \d+" | cut -d" " -f2)
		command=$(ps -efq ${pid} --no-headers | grep -Po "ssh .*")
		nt_ssh_list[$[$z + 1]]="%COMMAND: ${command}"
		z=$[$z + 2]
	done

	# PRINT BLOCK
	clear
	echo    "------------------ WhereMyTunnels V0.3 -------------------" > $ssh_status
	echo -e "------------------ Written by Androsh7 -------------------\n" >> $ssh_status
	# print tunnels
	echo -e "Traditional Tunnels: ${CYAN}" >> $ssh_status
	for ((i = 0 ; i < ${#tunnel_list[@]} ; i++)); do
		echo ${tunnel_list[${i}]} | sed -e 's/%/\t/g' >> $ssh_status
	done
	echo -e "${NC}" >> $ssh_status

	# print master sockets and forwards
	echo -e "Master sockets and forwards: ${CYAN}" >> $ssh_status
	for ((i = 0 ; i < ${#socket_list[@]} ; i++)); do
		echo ${socket_list[${i}]} | sed -e 's/%/\t/g' >> $ssh_status
	done
	echo -e "${NC}" >> $ssh_status

	# print non-tunnel ssh sessions
	echo -e "Non-tunnel ssh sessions: ${CYAN}" >> $ssh_status
	for ((i = 0 ; i < ${#nt_ssh_list[@]} ; i++)); do
		echo ${nt_ssh_list[${i}]} | sed -e 's/%/\t/g' >> $ssh_status
	done
	echo -e "${NC}" >> $ssh_status
	cat $ssh_status
	sleep 0.5
done
