#!/usr/bin/python3
import os
import re

ps_command = r'ps -ao pid,args -w --no-headers | grep "[s]sh .*" > /tmp/ssh_ps'
ss_command = r'ss -nap | grep "ssh\"" > /tmp/ssh_ss'

example_MS = "18703 ssh -MS /tmp/mysock student@10.50.35.141"
example_S =  "18706 ssh -S /tmp/mysock mysock -L 1111:127.0.0.1:22"

ps_list = []
ss_list = []
ms_list = []

def get_process_by_pid (pid):
    for line in ps_list:
        if line[1] == pid:
            return line

def get_socket_by_pid (pid):
    for line in ss_list:
        if line[1] == pid:
            return line

def debug_print():
    print("----- DEBUG PRINT -----")
    print("PROCESS LIST:")
    for line in ps_list:
        print(line)
    print("SOCKET LIST:")
    for line in ss_list:
        print(line)
    print("MASTER LIST:")
    for line in ms_list:
        print(line)
    print("----- DEBUG PRINT -----")

while True:

    # writes commands to a file
    os.system(ps_command)
    os.system(ss_command)

    # Creates Process List
    with open('/tmp/ssh_ps', 'r') as file_handler:
        for line in file_handler:
            print(line)
            line = line.strip()
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
                    socket_file = re.search('S [a-zA-Z_/][\w+/]+', command).group().split(" ")[1]
                    destination = re.search('(\d{1,3}\.){3}\d{1,3}( -p ?\d+)?', command).group()
                    user_match = re.search('\w+@', command)
                    if user_match:
                        username = user_match.group().split("@")[0]
                    else:
                        username = "CURR_USER"

                    port = re.search('-p.*', destination)
                    if not port:
                        port = "22"
                    else:
                        port = port.group().split("p")[1].strip()

                    argument.append(socket_file)
                    argument.append(username)
                    argument.append(destination)
                    argument.append(port)
                
                # Socket Forward
                else:
                    ssh_type = "S"
                    socket_stuff = re.search('S [/\w]+ \w+', command).group().split(" ")[1:]
                    print("Socket_stuff = ", type(socket_stuff))
                    socket_file = socket_stuff[0]
                    socket_name = socket_stuff[1]
                    print(type(socket_file))
                    argument.append(socket_file)
                    argument.append(socket_name)

                    # find source and dest ports
                    src_dest = re.search("\d+:(\d{1,3}\.){3}\d{1,3}:\d+", command).group().split(":")
                    src = src_dest[0]
                    dst = src_dest[2]
                    argument.append(src)
                    argument.append(dst)

                    print("arg", argument)

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
                        port = port.group().split("p")[1].strip()

                    argument.append(username)
                    argument.append(destination)
                    argument.append(port)

                    forward_list = re.findall('[LR] ?\d+:[\w\.]+:\d+', command)
                    for raw_forward in forward_list:
                        trim_forward = raw_forward[1:].lstrip().split(":")
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

            # Other Sessions
            else:
                ssh_type = "SH"
                destination = re.search('(\d{1,3}\.){3}\d{1,3}( -p ?\d+)?', command).group()
                print("dest", destination.split(" ")[-1])
                user_match = re.search('\w+@', command)
                if user_match:
                    username = user_match.group().split("@")[0]
                else:
                    username = "CURR_USER"

                port = re.search('-p.*', destination)
                if not port:
                    port = "22"
                else:
                    port = destination.split(" ")[-1]

                argument.append(username)
                argument.append(destination.split(" ")[0])
                argument.append(port)


            out_process = [0, pid, ssh_type, command, argument]
            ps_list.append(out_process)
    
    # Creating Socket List
    with open('/tmp/ssh_ss', 'r') as file_handler:
        for line in file_handler:
            print(line)
            line = line.rstrip()
            #print("line:", line)
            pid = re.search('pid=\d+', line).group().split("=")[1]
            socket_type = re.search('^\w+ +\w+', line).group()

            # Master Sockets
            if re.search('^u_str', socket_type):
                if re.search('ESTAB', socket_type):
                    socket_type = 'u_strESTAB'
                elif re.search('LISTEN', line):
                    socket_type = 'u_strLISTEN'

                socket = re.search('[/\w]+\.[a-zA-Z0-9]{5,} \d+', line)
                if socket:
                    socket_file = socket.group().split(".")[0]
                    socket_code = socket.group().split(" ")[1]
                else:
                    socket_file = "*"
                    socket_code = "*"


                out_process = [0, pid, socket_type, socket_file, socket_code]
                ss_list.append(out_process)
                continue

            # Traditional Tunnels and Other Sessions
            if re.search('tcp +LISTEN', socket_type):
                socket_type = "tcp_LISTEN"
            elif re.search('tcp +ESTAB', socket_type):
                socket_type = "tcp_ESTAB"

            src_dest = re.search('(\d+\.){3}\d+:\d+ +(\d+\.){3}\d+:[\d+\*]+', line)
            if not src_dest:
                continue
            else:
                src = src_dest.group().split(" ")[0].strip()
                dst = "".join(src_dest.group().split(" ")[1:])

            out_socket = [0, pid, socket_type, src, dst]
            ss_list.append(out_socket)
    
    # build master_list
    # [ parent_index, type, ps_list, ss_list ]

    # adds all master sockets
    for i in range(len(ss_list)):
        if ss_list[i][2] == "u_strLISTEN" and ss_list[i][0] == 0:
            ss_list[i][0] = 1
            master_socket = [len(ms_list), "MS", "", ss_list[i]]

            # find connected process via socket
            socket = ss_list[i][3]
            for ps_line in ps_list:
                if ps_line[0] == 0 and ps_line[2] == "MS" and ps_line[4][0] == socket:
                    ps_line[0] = 1
                    master_socket[2] = ps_line

            # add the completed item to the master list
            ms_list.append(master_socket)
    
    # adds all socket forwards
    for i in range(len(ss_list)):
        if ss_list[i][2] == "tcp_LISTEN" and ss_list[i][0] == 0:
            ss_list[i][0] = 2
            socket_forward = [-1, "S_FWD", "", ss_list[i]]

            # find connected process via port
            port = ss_list[i][3].split(":")[1]
            for ps_line in ps_list:
                if ps_line[0] == 0 and ps_line[2] == "S" and ps_line[4][2] == port:
                    ps_line[0] = 2
                    socket_forward[2] = ps_line

            # determine parent socket
            socket = socket_forward[2][4][0]
            for i in range(len(ms_list)):
                if ms_list[i][1] == "MS" and ms_list[i][3][3] == socket:
                    socket_forward[0] = i
                    break
            ms_list.append(socket_forward)

    # print lists
    MS_print = []
    TRAD_print = []
    SH_print = []

    # establish master socket and socket forward dependencies
    # also include formatting
    for i in range(len(ms_list)):
        if ms_list[i][0] >= 0 and ms_list[i][1] == "MS":
            MS_print.append(f"{ms_list[i][3][3]} --> {ms_list[i][2][4][2]}:{ms_list[i][2][4][3]} - PID {ms_list[i][2][1]}")
            for z in range(len(ms_list)):
                if ms_list[z][0] == i and ms_list[z][1] == "S_FWD":
                    MS_print.append(f"\t{ms_list[z][3][3]} --> {ms_list[z][3][4]}")
    
    os.system("clear")
    print("-" * 10, "WhereMyTunnels V0.4", "-" * 10)
    print("-" * 10, "Written by Androsh7", "-" * 10, "\n")
    

    # Master Socket Print Block
    if len(MS_print):
        print("Master Sockets and Forwards:", "\033[1;34m")
        for line in MS_print:
            print(line)
        print("\033[0m")

    # Traditional Tunnel Print Block
    if len(TRAD_print):
        print("Traditional Tunnels:")
        for line in TRAD_print:
            print(line)

    # Standard Session Print Block
    if len(SH_print):
        print("Standard SSH Sessions")
        for line in SH_print:
            print(line)

    ps_list.clear()
    ss_list.clear()
    ms_list.clear()

    MS_print.clear()
    TRAD_print.clear()
    SH_print.clear()

    os.system("sleep 1")
