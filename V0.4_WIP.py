#!/usr/bin/python3
import os
import re

ps_command = r'ps -ao pid,args -w --no-headers | grep "[s]sh .*" > /tmp/ssh_ps'
ss_command = r'ss -nap | grep "ssh\"" > /tmp/ssh_ss'

example_MS = "18703 ssh -MS /tmp/mysock student@10.50.35.141"
example_S =  "18706 ssh -S /tmp/mysock mysock -L 1111:127.0.0.1:22"

while True:

    # writes commands to a file
    os.system(ps_command)
    os.system(ss_command)

    # reads the process list
    ps_list = []
    with open('/tmp/ssh_ps', 'r') as file_handler:
        for line in file_handler:
            line = line.rstrip()
            pid = (re.split(" ", line, 1))[0]
            command = (re.split(" ", line, 1))[1]

            # get the type
            ssh_type = "" # attempt to detect MS (Master Socket), S (Socket), TD (Traditional, SH (Other Session)
            argument = []

            # Master Sockets and Forwards
            if re.search('ssh -\w*S\w*', command):
                # Master Socket
                if re.search('ssh -\w*M\w*', command):
                    ssh_type = "MS"
                    socket_file = str(re.search('S [a-zA-Z_/][\w+/]+', command).group().split(" ")[1])
                    destination = re.search('(\d{1,3}\.){3}\d{1,3}( -p ?\d+)?', command).group()
                    user_match = re.search('\w+@', command)
                    if user_match:
                        username = user_match.group().split("@")[0]
                    else:
                        username = "CURRENT_USER"

                    port = re.search('-p.*', destination)
                    if not port:
                        port = "22"
                    else:
                        port = re.search('\d+', destination.split(" ")[1:]).group()

                    argument.append(socket_file)
                    argument.append(username)
                    argument.append(destination)
                    argument.append(port)
                # Forward
                else:
                    ssh_type = "S"
                    socket_stuff = str(re.search('S [/\w]+ \w+', command).group().split(" ")[1:])
                    socket_file = socket_stuff[0]
                    socket_name = socket_stuff[1]

                    argument.append(socket_file)
                    argument.append(socket_name)


            # Traditional Tunnel
            elif re.search('ssh .* -[LD] ?\d+', command):
                    ssh_type = "TD"
                    destination = re.search('(\d{1,3}\.){3}\d{1,3}( -p ?\d+)?', command).group()
                    user_match = re.search('\w+@', command)
                    if user_match:
                        username = user_match.group().split("@")[0]
                    else:
                        username = "CURRENT_USER"

                    port = re.search('-p.*', destination)
                    if not port:
                        port = "22"
                    else:
                        port = re.search('\d+', destination.split(" ")[1:]).group()

                    argument.append(username)
                    argument.append(destination)
                    argument.append(port)

                    forward_list = re.findall('[LR] ?\d+:[\w\.]+:\d+', command)
                    print("FWD LIST:", forward_list)
                    for raw_forward in forward_list:
                        trim_forward = raw_forward[1:].lstrip().split(":")
                        print("raw_forward", raw_forward, trim_forward)
                        if raw_forward[0] == "L":
                            forward = [ trim_forward[0], trim_forward[1], trim_forward[2] ]
                        else:
                            forward = [ trim_forward[2], trim_forward[1], trim_forward[0] ]
                        argument.append(forward)

                    dynamic_list = re.findall('D ?\d+', command)
                    for raw_dynamic in dynamic_list:
                        port_dynamic = raw_dynamic[1:].lstrip()
                        dynamic = [ port_dynamic, "127.0.0.1", "DYNAMIC" ]
                        argument.append(dynamic)

            else:
                ssh_type = "UNK"

            out_process = [pid, ssh_type, command, argument]
            ps_list.append(out_process)

    ss_list = []
    with open('/tmp/ssh_ss', 'r') as file_handler:
        for line in file_handler:
            line = line.rstrip()
            #print("line:", line)
            pid = re.search('pid=\d+', line).group().split("=")[1]
            socket_type = re.search('^\w+ +\w+', line).group()

            if re.search('^u_str', socket_type):
                if re.search('strESTAB', socket_type):
                    socket_type = 'u_strESTAB'
                elif re.search('strLISTEN', line):
                    socket_type = 'u_strLISTEN'

                socket = re.search('[/\w]+\.[a-zA-Z0-9]{5,} \d+', line).group()
                socket_file = socket.split(".")[0]
                socket_code = socket.split(" ")[1]

                out_process = [pid, socket_type, socket_file, socket_code]
                ss_list.append(out_process)
                continue

            if socket_type == "tcp  LISTEN":
                socket_type = "tcp_LISTEN"
            elif socket_type == "tcp  ESTAB":
                socket_type = "tcp_ESTAB"

            src_dest = re.search('(\d+\.){3}\d+:\d+ +(\d+\.){3}\d+:[\d+\*]+', line)
            if not src_dest:
                continue
            else:
                src = src_dest.group().split(" ")[0].strip()
                dst = "".join(src_dest.group().split(" ")[1:])

            out_process = [pid, socket_type, src, dst]
            ss_list.append(out_process)

    # print everything
    print("PROCESS LIST: ")
    for line in ps_list:
        print(line)
    print("SOCKET LIST: ")
    for line in ss_list:
        print(line)
    exit()
