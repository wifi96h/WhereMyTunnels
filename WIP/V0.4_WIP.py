#!/usr/bin/python3
import os
import re

ps_command = r'ps -ao pid,args -w --no-headers | grep "[s]sh .*" > /tmp/ssh_ps'
ss_command = r'ss -nap | grep "ssh\"" > /tmp/ssh_ss'

example_MS = "18703 ssh -MS /tmp/mysock student@10.50.35.141"
example_S =  "18706 ssh -S /tmp/mysock mysock -L 1111:127.0.0.1:22"

ps_list = []
ss_list = []

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
    print("----- DEBUG PRINT -----")

while True:

    # writes commands to a file
    os.system(ps_command)
    os.system(ss_command)

    # reads the process list
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


            out_process = [0, pid, ssh_type, command, argument]
            ps_list.append(out_process)

    with open('/tmp/ssh_ss', 'r') as file_handler:
        for line in file_handler:
            line = line.rstrip()
            #print("line:", line)
            pid = re.search('pid=\d+', line).group().split("=")[1]
            socket_type = re.search('^\w+ +\w+', line).group()

            # Master Socekts
            if re.search('^u_str', socket_type):
                if re.search('strESTAB', socket_type):
                    socket_type = 'u_strESTAB'
                elif re.search('strLISTEN', line):
                    socket_type = 'u_strLISTEN'

                socket = re.search('[/\w]+\.[a-zA-Z0-9]{5,} \d+', line).group()
                socket_file = socket.split(".")[0]
                socket_code = socket.split(" ")[1]

                out_process = [0, pid, socket_type, socket_file, socket_code]
                ss_list.append(out_process)
                continue

            # Traditional Tunnels and Other Sessions
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

            out_socket = [0, pid, socket_type, src, dst]
            ss_list.append(out_socket)


    # organizing master sockets
    MS_print = []
    for socket in ss_list:
        if socket[0] != 0 or socket[2] != "u_strLISTEN":
            continue
        socket[0] = 1
        master_pid = socket[1]
        master_sock = socket[3]

        # master process and formatting
        master_proc = get_process_by_pid(master_pid)
        master_proc[0] = 1
        MS_print.append(f"{master_sock} --> {master_proc[4][1]}@{master_proc[4][2]}:{master_proc[4][3]} - PID {master_pid}")

        # get attached stuff
        for socket in ss_list:
            if socket[0] != 0 or socket[1] != master_pid:
                continue
            socket[0] = 2
            if socket[2] == "tcp_LISTEN":
                MS_print.append(f"\tFORWARD: {socket[3]} --> UNK")
            else:
                MS_print.append(f"\tSESSION: {socket[3]} --> {socket[4]}")

    # organizing traditional sockets
    TRAD_print = []
    for socket in ss_list:
        if socket[0] != 0 or socket[2] != "tcp_LISTEN":
            continue
        master_pid = socket[1]

        # master process and formatting
        master_proc = get_process_by_pid(master_pid)
        master_proc[0] = 3
        TRAD_print.append(f"TRAD TUNNEL --> {master_proc[4][0]}@{master_proc[4][1]}:{master_proc[4][2]} - PID {master_pid}")
        # verify forwards
        for i in range(3,len(master_proc[4])):
            # check for socket connection
            found_match = False
            for socket in ss_list:
                if socket[0] != 0 or socket[2] != "tcp_LISTEN" or socket[1] != master_pid or socket[3] != f"127.0.0.1:{master_proc[4][i][0]}":

                    continue
                print(socket[3], " == ", f"127.0.0.1:{master_proc[4][i][0]}")
                found_match = True
                break
            if found_match:
                TRAD_print.append(f"\tFORWARD: 127.0.0.1:{master_proc[4][i][0]} --> {master_proc[4][i][1]}:{master_proc[4][i][2]}")
                socket[0] = 3
            else:
                TRAD_print.append(f"\tERROR: 127.0.0.1:{master_proc[4][i][0]} --> {master_proc[4][i][1]}:{master_proc[4][i][2]} ERROR")

        # get attached sessions
        for socket in ss_list:
            if socket[0] != 0 or socket[1] != master_pid:
                continue
            socket[0] = 2
            MS_print.append(f"\tSESSION: {socket[3]} --> {socket[4]}")

    SH_print = []
    # other tunnels
    for socket in ss_list:
        if socket != 0 or socket[2] != "tcp_ESTAB":
            continue
        socket[0] = 4
        session_proc = get_process_by_pid(socket[1])
        session_proc[0] = 4
        SH_print.append(f"{socket[3]} --> {socket[4]} - PID {socket[1]}")
        SH_print.append(f"\t{session_proc[3]}")

    MAL_print = []
    # malformed tunnels
    for process in ps_list:
        MAL_print.append(f"{process[3]} - PID {process[1]}")


    # print header
    os.system("clear")
    print("------------------ WhereMyTunnels V0.4 -------------------")
    print("------------------ Written by Androsh7 -------------------\n")

    # print master sockets
    if len(MS_print):
        print("MASTER SOCKETS AND FORWARDS:")
        for line in MS_print:
            print(line)

    # print traditional tunnels
    if len(TRAD_print):
        print("TRADITIONAL TUNNELS:")
        for line in TRAD_print:
            print(line)

    # print other sessions
    if len(SH_print):
        print("OTHER SESSIONS:")
        for line in SH_print:
            print(line)

    # print malformed sessions
    if len(SH_print):
        print("MALFORMED SESSIONS:")
        for line in MAL_print:
            print(line)

    os.system("sleep 1")
