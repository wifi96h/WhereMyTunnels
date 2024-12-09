#!/usr/bin/python3
import re
import os
import time

'''
WhereMyTunnels.sh v0.5 written by Androsh7
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
'''

ps_file = "/tmp/ssh_ps" # ssh proccesses are written to this file
ss_file = "/tmp/ssh_ss" # ssh sockets are written to this file

debug = False # enables the debug printing

ps_command = r'ps -ao user,pid,args -w --no-headers | grep "[s]sh .*" > ' + ps_file
ss_command = r'ss -nap | grep "ssh\"" > ' + ss_file

ps_list = []
ss_list = []
ms_list = []
malformed_list = []

def get_process_by_pid (pid):
    for line in ps_list:
        if line["pid"] == pid:
            return line
    if debug : print("Could not find process with pid", pid)
    
def get_process_by_src_port (type, src_port):
    for line in ps_list:
        if line["type"] == type and line["src_port"] == src_port:
            return line
    if debug : print("Could not find process with a type of", type, "and a source port of", src_port)
    
def get_socket_by_pid (pid):
    for line in ss_list:
        if line["pid"] == pid:
            return line
    if debug : print("Could not find socket with pid", pid)
    

def debug_print ():
    print("----- DEBUG PRINT -----")
    print("PROCESS LIST:")
    for line in ps_list:
        print(line)
    print("SOCKET LIST:")
    for line in ss_list:
        print(line)
    print("MASTER LIST")
    for line in ms_list:
        print(line)
    print("----- DEBUG PRINT -----")
    
def clear_screen ():
    os.system("clear") # Switch to test on windows

blue = "\033[1;34m"
red = "\033[1;31m"
RST_color = "\033[0m"

#  /--------------------------------------------------------------------------------\
# |                       CLI RENDERING ENGINE - By Androsh7                         |
# |                    Github.com/Androsh7/CLI_Rendering_Engine                      |
#  \--------------------------------------------------------------------------------/

# dictionary for cli color codes
cli_color = {
    "reset": "\033[0m",

    # standard colors
    "black": "\033[30m",
    "blue": "\033[34m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "red": "\033[31m",
    "purple": "\033[35m",
    "brown": "\033[33m",
    "yellow": "\033[1;33m",
    "white": "\033[1;37m",

    # light/dark colors
    "light_gray": "\033[33[37m",
    "dark_gray": "\033[33[1;30m",
    "light_blue": "\033[33[1;34m",
    "light_green": "\033[33[1;32m",
    "light_cyan": "\033[33[1;36m",
    "light_red": "\033[33[1;31m",
    "light_purple": "\033[33[1;35m",

    # highlights
    "black_highlight": "\033[40m",
    "red_highlight": "\033[41m",
    "green_highlight": "\033[42m",
    "yellow_highlight": "\033[43m",
    "blue_highlight": "\033[44m",
    "purple_highlight": "\033[45m",
    "cyan_highlight": "\033[46m",
    "white_highlight": "\033[47m",
}

class cli_render:
    start_line = 1 # y-offset to start printing on
    line_counter = start_line # keeps track of the current y-offset
    rendered_lines = [] # this stores all rendered lines
    prev_rendered_lines = []  # this stores all previously rendered lines

    @classmethod
    # clears the screen without moving the cursor
    def clear_screen(self):
        print("\033[2J", end="", sep="")
    
    @classmethod
    # sets the cursor position
    # NOTE: the starting position for the terminal is (0,1)
    def set_cursor(self, x_cord, y_cord):
        # check to ensure valid position
        if x_cord < 0 or y_cord < 0: 
            print("invalid cursor position from set_cursor to ({},{})".format(x_cord, y_cord))
            return 1
        print("\033[{};{}H".format(int(y_cord), int(x_cord)), end="", sep="")
    
    @classmethod
    # move cursor horizontally
    # WARNING NO INPUT VALIDATION
    def move_cursor_horz(self, x_change):
        if x_change > 0:
            print("\033[{}C".format(x_change), end="", sep="")
        elif x_change < 0:
            print("\033[{}D".format(x_change * -1), end="", sep="")
    
    @classmethod
    # move cursor vertically
    # WARNING NO INPUT VALIDATION
    def move_cursor_vert(self, y_change):
        if y_change > 0:
            print("\033[{}B".format(y_change), end="", sep="")
        elif y_change < 0:
            print("\033[{}A".format(y_change * -1), end="", sep="")

    @classmethod
    # prints a single line and increments the line_counter
    def print_line(self, print_line):
        self.set_cursor(0, self.line_counter)
        print(print_line, end="", sep="")

        # stores previously printed lines
        trimmed_line = re.sub("\033.*[a-zA-Z]", "", print_line) # this removes color formatting
        self.rendered_lines.append(trimmed_line)

        # grabs the length of the previous line, if one exists
        prev_len = 0
        if len(self.prev_rendered_lines) > self.line_counter:
            prev_len = self.prev_rendered_lines[self.line_counter]

        # pads the difference in length between the current line and the previous line
        if len(trimmed_line) < prev_len:
            padding = len(trimmed_line) - prev_len
            print(" " * padding, end="", sep="")
        
        print("\n", end="", sep="") # this prevents issues with lines not rendering

        self.line_counter += 1
    
    @classmethod
    # clear lines
    def clear_lines(self):
        while self.line_counter < len(self.prev_rendered_lines):
            padding = len(self.prev_rendered_lines[self.line_counter])
            print(" " * padding)

    @classmethod
    # reset class parameters
    def reset(self):
        self.prev_rendered_lines.clear()
        self.prev_rendered_lines = self.rendered_lines
        self.rendered_lines.clear()
        self.line_counter = self.start_line

cli = cli_render

#  /--------------------------------------------------------------------------------\
# |                       CLI RENDERING ENGINE - By Androsh7                         |
# |                    Github.com/Androsh7/CLI_Rendering_Engine                      |
#  \--------------------------------------------------------------------------------/

# initialize the window
cli.clear_screen()
cli.set_cursor(0,1)

# given the full process command (ssh ...) this function grabs the username, dest_ip, and dest_port (if specified) and returns it as a dictionary
# note the extra space to the left of the ip address regex is so it doesn't return the forwarding ip address, which looks like so "22:127.0.0.1:44" the addition of the space prevents this
def strip_dest_info(command, proc_user):
    destination = re.search(' (\d{1,3}\.){3}\d{1,3}( -p ?\d+)?', command).group().lstrip()
    # tries to remove the port, if it isn't specified then assume it is 22 and keep the destination as is
    # if the port is specified, then use regex to seperate the ip and port from the destination string
    port = re.search('-p.*', destination)
    if not port:
        dest_port = "22" # the default for ssh is to assume port 22
        dest_ip = destination
    else:
        destination = re.split(' -p ?', destination) # splits the destination into the ip and port
        dest_ip = destination[0] # removes the port from the destination
        dest_port = destination[1] # grabs the port from the destination
    
    # detects if a user is specified
    # if no user is specified then the current user is the one signing in to the destination machine
    user_match = re.search('\w+@', command)
    if user_match:
        username = user_match.group().split("@")[0]
    else:
        username = proc_user # This is the user that owns the ssh process
        
    return {
        "username" : username,
        "dest_ip" : dest_ip,
        "dest_port" : dest_port
    }

def strip_forward_info (command):
    forward_list =[]
    regular_forwards = re.findall('(-\w*[LR]\w* ?\d{1,6}:(\d{1,3}\.){3}\d{1,3}:\d{1,6})', command)
    for line in regular_forwards:
        line = line[0]
        
        # determine the forward type and assign src_port, dest_ip, and dest_port
        forward_srcdest = re.search('\d{1,6}:(\d{1,3}\.){3}\d{1,3}:\d{1,6}', line).group().split(":")
        if re.search('-\w*L\w*', line):
            forward_type = "local"
            src_port = forward_srcdest[0]
            dest_ip = forward_srcdest[1]
            dest_port = forward_srcdest[2]
        elif re.search('-\w*R\w*', line):
            # note for reverse forwards the port assignments are reversed since they are created from the perspective of the remote machine
            forward_type = "remote"
            dest_port = forward_srcdest[0]
            dest_ip = forward_srcdest[1]
            src_port = forward_srcdest[2]
        else:
            if debug : print("could not identify forward type")
            continue
        
        # build forward entry
        forward = {
            "type" : forward_type,
            "src_port" : src_port,
            "dest_ip" : dest_ip,
            "dest_port" : dest_port,
            "socket" : {},
        }
        forward_list.append(forward)
    
    dynamic_forwards = re.findall('-\w*D\w* ?\d{1,6}', command)
    for line in dynamic_forwards:
        if debug : print("DYNAMIC FORWARDS ARE NOT CURRENTLY SUPPORTED")
    
    return forward_list

repetitions = 0 # this counts the number of repetitions for the main while loop
while True:

    # writes commands to a file
    os.system(ps_command)
    os.system(ss_command)

    # reads the process file
    if debug : print("----- Reading ssh_ps -----")
    with open(ps_file, 'r') as file_handler:
        for line in file_handler:
            try:
                if debug : print("Reading line: ", line)
                line = re.sub(' +', ' ', line) # Condenses multiple spaces into one space
                line = line.strip()

                # Line format is: "USER PID COMMAND"
                user = (re.split(" ", line, 2))[0] # USER|PID COMMAND, "|" represents the location of the split
                pid = (re.split(" ", line, 2))[1] # USER|PID|COMMAND
                command = (re.split(" ", line, 2))[2] # USER|PID|COMMAND

                # Master Sockets and Forwards
                if re.search('ssh -\w*S\w*', command):
                    # Master Socket
                    if re.search('ssh -\w*M\w*', command):
                        socket_file = str(re.search('S [a-zA-Z_/][\w+/]+', command).group().split(" ")[1])
                        
                        dest_info = strip_dest_info(command, user)
                        
                        # Formatting
                        out_process = {
                            "org_num" : 0, # used for organization
                            "pid" : pid,
                            "type" : "MS", # master socket
                            "command" : command,
                            "socket_file" : socket_file,
                            "user" : dest_info["username"],
                            "dest_ip" : dest_info["dest_ip"],
                            "dest_port" : dest_info["dest_port"],
                        }
                        ps_list.append(out_process)
                    # Forward
                    else:
                        # socket_stuff is the combination of the socket file and the forward name
                        # I.E: /tmp/mysock mysock
                        socket_stuff = re.search('S [/\w]+ \w+', command).group().split(" ")[1:]
                        socket_file = socket_stuff[0]
                        forward_name = socket_stuff[1]
                                            
                        forwards = strip_forward_info(command)
                        
                        out_process = {
                            "org_num" : 0,
                            "pid" : pid,
                            "type" : "S", # master socket forward type
                            "command" : command,
                            "socket_file" : socket_file,
                            "forward_name" : forward_name, # this is the actual label for the forward
                            "forwards" : forwards
                        }
                        ps_list.append(out_process)

                # Traditional Tunnel
                elif re.search('ssh .* -[LR] ?\d+', command):
                    dest_info = strip_dest_info(command, user)
                    forwards = strip_forward_info(command)
                    out_process = {
                        "org_num" : 0,
                        "pid" : pid,
                        "type" : "TD", # traditional forward
                        "command" : command,
                        "user" : dest_info["username"],
                        "dest_ip" : dest_info["dest_ip"],
                        "dest_port" : dest_info["dest_port"],
                        "forwards" : forwards
                    }
                    ps_list.append(out_process)
                # Other Sessions
                else:
                    dest_info = strip_dest_info(command, user)
                
                    # Formatting
                    out_process = {
                        "org_num" : 0, # used for organization
                        "pid" : pid,
                        "type" : "SH", # regular session
                        "command" : command,
                        "user" : dest_info["username"],
                        "dest_ip" : dest_info["dest_ip"],
                        "dest_port" : dest_info["dest_port"]
                    }
                    ps_list.append(out_process)
            except:
                if debug : print("MALFORMED SESSION")
                malformed_list.append(line)
    
    # read the socket file
    if debug : print("----- reading ssh_ss -----")
    with open(ss_file, 'r') as file_handler:
        for line in file_handler:
            try:
                if debug : print("reading line: [{}]".format(line))
                line = line.rstrip()

                pid = re.search('pid=\d+', line).group().split("=")[1]
                
                # this find the initial label for the type of socket I.E: "tcp  LISTEN"
                # this section also uses the regex substitution method to remove all spaces
                socket_type = re.sub(' ', '', re.search('^\w+ +\w+', line).group())

                # Master Socekts
                if re.search('^u_str', socket_type):
                    # this is a little strange to explain, most master sockets have this in the middle: "/tmp/test.BiD6RlLl7ZqhQS2w" 
                    # it includes the socket file and a unique alphanumeric string
                    # however some have this instead "*", these are duplicates and should be ignored for our purposes
                    try:
                        socket = re.search('[/\w]+\.[a-zA-Z0-9]{5,} \d+', line).group()
                    except:
                        if debug : print("Unknown Socket Detected, ignoring socket")
                        continue
                    
                    # see the above documentation for an explanation, this breaks up the socket_file I.E: "/tmp/test" and the socket_code I.E: "BiD6RlLl7ZqhQS2w"
                    # currently there is no use for the socket_code in the program
                    socket_file = socket.split(".")[0]
                    socket_code = socket.split(" ")[1]

                    out_socket = {
                        "org_num" : 0,
                        "pid" : pid,
                        "type" : socket_type,
                        "socket_file" : socket_file,
                        "socket_code" : socket_code,
                    }
                    ss_list.append(out_socket)
                    continue

                # Traditional Tunnels and Other Sessions
                src_dest = re.search('(\d+\.){3}\d+:\d+ +(\d+\.){3}\d+:[\d+\*]+', line) # example result: "127.0.0.1:1111 0.0.0.0:*"
                
                # this aborts if no source and destination is found
                if not src_dest:
                    if debug : print("Could not find a valid source and/or destination ip for the socket, ignoring socket")
                    continue 

                # this section is all about breaking apart the src_dest into, src_port, src_ip, dst_port, dst_ip
                src_dest = re.split(' +', src_dest.group()) # this splits the src_dest string in half (src and dest) by the space in the middle
                
                # little complicated, here is the breakdown:
                # src_dest = ["127.0.0.1:1111", "0.0.0.0:*"]
                # each of these are then broken down by the ":"
                src_ip = src_dest[0].split(":")[0] 
                src_port = src_dest[0].split(":")[1]
                dest_ip = src_dest[1].split(":")[0]
                dest_port = src_dest[1].split(":")[1] # note this may be "*" since listening ports do not have a specified destination
                
                out_socket = {
                    "org_num" : 0,
                    "pid" : pid,
                    "type" : socket_type,
                    "src_ip" : src_ip,
                    "src_port" : src_port,
                    "dest_ip" : dest_ip,
                    "dest_port" : dest_port,
                }
                if debug : print("Creating Socket: [{}]".format(out_socket))
                ss_list.append(out_socket)
            except:
                pass
    
    # create master list
    
    # add master sockets, socket forwards, and associated sessions into master list
    for master_process in ps_list:
        if master_process["org_num"] == 0 and master_process["type"] == "MS":
            master_socket = get_socket_by_pid(master_process["pid"]) # grab the associated socket
           
            # if no socket is attached then the process is malformed
            if not master_socket:
                if debug : print("MALFORMED Master Socket Detected")
                malformed_list.append("{} - PID {}".format(master_process["command"], master_process["pid"]))
                master_process["org_num"] = -2 # mark is malformed
                continue
            
            # additional check to ensure valid selection
            try:
                if not (master_socket["socket_file"] == master_process["socket_file"]):
                    if debug : print("Master socket with matching socket and process pids do not have matching socket_file :(")
                    continue
            except:
                break

            master_process["org_num"] = 1 # mark as sorted
            master_socket["org_num"] = 1 # mark as sorted
            
            master_entry = {
                "org_num" : 0,
                "pid" : master_socket["pid"],
                "type" : "MS",
                "process" : master_process,
                "socket" : master_socket,
                "attached" : [], # this is where all the socket forwards and sessions are attached
            }
            ms_list.append(master_entry)
            
            # find attached forwards
            for child_process in ps_list:
                if child_process["org_num"] == 0 and child_process["type"] == "S" and child_process["socket_file"] == master_process["socket_file"]:
                    
                    child_process["org_num"] = 1 # mark as sorted

                    # go through each forward and attempt to find a matching socket connection
                    
                    found_socket = False
                    for forward_process in child_process["forwards"]:
                        # find the forward's associated socket
                        for forward_socket in ss_list:
                            if forward_socket["org_num"] == 0 and forward_socket["type"] == "tcpLISTEN" and forward_socket["pid"] == master_process["pid"] and forward_socket["src_port"] == forward_process["src_port"]:
                                forward_socket["org_num"] = 1 # mark as sorted
                                forward_process["socket"] = forward_socket
                                found_socket = True
                                break
                        if not found_socket:
                            if debug : print("could not find socket associated with forward")
                            forward_process["type"] = "MALFORMED"
                    
                    child_entry = {
                        "org_num" : 0,
                        "pid" : child_process["pid"],
                        "type" : "S_FWD",
                        "process" : child_process
                    }
                    master_entry["attached"].append(child_entry)
                
            # find attached sessions
            for child_socket in ss_list:
                if child_socket["org_num"] == 0 and child_socket["pid"] == master_process["pid"]:
                    if child_socket["type"] == "tcpESTAB":
                        
                        child_socket["org_num"] = 1 # mark as sorted
                        
                        child_entry = {
                            "org_num" : 0,
                            "pid" : child_socket["pid"],
                            "type" : "S_SH",
                            "src_ip" : child_socket["src_ip"],
                            "src_port" : child_socket["src_port"],
                            "dest_ip" : child_socket["dest_ip"],
                            "dest_port" : child_socket["dest_port"],
                        }
                        master_entry["attached"].append(child_entry)
                    elif child_socket["type"] == "u_strESTAB":
                        child_socket["org_num"] = -1 # mark as ignored
                        
    
    # add traditional forwards to the master list
    for process in ps_list:
        if process["org_num"] == 0 and process["type"] == "TD":
            process["org_num"] = 1 # mark as sorted
            
            entry = {
                "org_num" : 0,
                "pid" : process["pid"],
                "type" : "TD",
                "process" : process,
                "attached" : []
            }
            ms_list.append(entry)
            
            # find sockets for the forwards
            for forward_process in process["forwards"]:
                # find each forward's associated socket
                found_socket = False
                for forward_socket in ss_list:
                    if forward_socket["org_num"] == 0 and forward_socket["type"] == "tcpLISTEN" and forward_socket["pid"] == process["pid"] and forward_process["src_port"] == forward_socket["src_port"]:
                        forward_process["socket"] = forward_socket
                        forward_socket["org_num"] = 1 # mark as sorted
                        found_socket = True
                
                if not found_socket:
                    if debug : print("could not find socket associated with forward")
                    forward_process["type"] = "MALFORMED"
            
            # find attached sessions
            for child_socket in ss_list:
                if child_socket["org_num"] == 0 and child_socket["pid"] == process["pid"] and child_socket["type"] == "tcpESTAB":
                    child_socket["org_num"] = 1 # mark as sorted

                    child_entry = {
                        "org_num" : 0,
                        "pid" : child_socket["pid"],
                        "type" : "S_SH",
                        "src_ip" : child_socket["src_ip"],
                        "src_port" : child_socket["src_port"],
                        "dest_ip" : child_socket["dest_ip"],
                        "dest_port" : child_socket["dest_port"],
                    }
                    entry["attached"].append(child_entry)

    # add regular sessions to the master list
    # NOTE: these are a lot simpler since the PIDs are unique
    for socket in ss_list:
        if socket["org_num"] == 0 and socket["type"] == "tcpESTAB":
            if debug : print(socket)

            # grab associated process
            process = get_process_by_pid(socket["pid"])
            
            if not process:
                if debug : print("could not find process with pid", socket["pid"])
                continue

            socket["org_num"] = 1 # mark as sorted
            process["org_num"] = 1 # mark as sorted
            
            # build ms_list entry
            ssh_entry = {
                "org_num" : 0,
                "pid" : socket["pid"],
                "type" : "SH",
                "process" : process,
                "socket" : socket
            }
            ms_list.append(ssh_entry)
    
    # clear the screen every 30 repetitions
    if not repetitions % 30:
        cli.clear_screen()

    cli.print_line('-' * 20 + " WhereMyTunnels V0.5 " + '-' * 20)
    cli.print_line('-' * 20 + "---- By Androsh7 ----" + '-' * 20)

    # print master sockets
    cli.print_line("Master Sockets and Forwards:" + cli_color["blue"])
    for item in ms_list:
        if item["type"] == "MS" and item["org_num"] == 0:
            cli.print_line("{} {}@{}:{} - PID {}".format(item["socket"]["socket_file"], item["process"]["user"], item["process"]["dest_ip"], item["process"]["dest_port"], item["pid"])) # MASTER SOCKET PRINT FORMAT
            
            # print all socket forwards
            for child_item in item["attached"]:
                if child_item["type"] == "S_FWD" and child_item["org_num"] == 0:
                    child_item["org_num"] = 1 # mark as printed
                    cli.print_line("    FWD Proc: \"{}\" - PID {}".format(child_item["process"]["forward_name"], child_item["pid"])) # SOCKET FORWARD PRINT FORMAT
                    for forward in child_item["process"]["forwards"]:
                        if forward["type"] == "MALFORMED" : print(cli_color["red"], end="")
                        cli.print_line("        FWD: 127.0.0.1:{} --> {}:{} - {}".format(forward["src_port"], forward["dest_ip"], forward["dest_port"], forward["type"]) +  + cli_color["blue"]) # FORWARD DATA PRINT

                        # find attached sessions
                        for session in item["attached"]:
                            if session["org_num"] == 0 and session["type"] == "S_SH" and session["src_port"] == forward["src_port"]:
                                session["org_num"] = 1 # mark as printed
                                cli.print_line("            SESSION: {}:{} --> {}:{}".format(session["src_ip"], session["src_port"],session["dest_ip"], session["dest_port"]))
            
            # print all remaining associated sessions
            for child_item in item["attached"]:
                if child_item["org_num"] == 0 and child_item["type"] == "S_SH":
                    pass
                    cli.print_line("    ASSOCIATED SESSION: {}:{} --> {}:{}".format(child_item["src_ip"], child_item["src_port"], child_item["dest_ip"], child_item["dest_port"])) # MASTER SOCKET SESSION PRINT FORMAT
    print(cli_color["reset"], end="")
    
    # print traditional forwards
    cli.print_line("Traditional Forwards:" + blue)
    for item in ms_list:
        if item["type"] == "TD" and item["org_num"] == 0:
            cli.print_line("FWD Proc: --> {}@{}:{} - PID {}".format(item["process"]["user"], item["process"]["dest_ip"], item["process"]["dest_port"], item["pid"])) # FORWARD PRINT FORMAT
            for forward in item["process"]["forwards"]:
                # change text to red for malformed forwards
                if forward["type"] == "MALFORMED" : print(red, end="")
                cli.print_line("    FWD: 127.0.0.1:{} --> {}:{} - {}".format(forward["src_port"], forward["dest_ip"], forward["dest_port"], forward["type"]))
                print(cli_color["blue"], end="")

                # find attached sessions
                for session in item["attached"]:
                    if session["org_num"] == 0 and session["type"] == "S_SH" and session["src_port"] == forward["src_port"]:
                        session["org_num"] = 1 # mark as printed
                        cli.print_line("        SESSION: {}:{} --> {}:{}".format(session["src_ip"], session["src_port"],session["dest_ip"], session["dest_port"]))

            # print all remaining associated sessions
            for child_item in item["attached"]:
                if child_item["org_num"] == 0 and child_item["type"] == "S_SH":
                    cli.print_line("    ASSOCIATED SESSION: {}:{} --> {}:{}".format(child_item["src_ip"], child_item["src_port"], child_item["dest_ip"], child_item["dest_port"])) # MASTER SOCKET SESSION PRINT FORMAT

    print(cli_color["reset"])
    
    # print regular sessions
    cli.print_line("Regular Sessions" + cli_color["blue"])
    for item in ms_list:
        if item["type"] == "SH" and item["org_num"] == 0:
            cli.print_line("SESSION: 127.0.0.1 --> {}:{} - PID {}".format(item["process"]["dest_ip"], item["process"]["dest_port"], item["pid"]))
            cli.print_line("    {}".format(item["process"]["command"][:150]))
    print(cli_color["reset"], end="")
    
    # print malformed sessions
    if len(malformed_list):
        cli.print_line("Malformed Sessions:")
        print(cli_color["red"], end="")
        for item in malformed_list:
            cli.print_line(item)
        print(cli_color["reset"], end="")
    
    if debug : debug_print()
    
    # cleaning lists
    ps_list.clear()
    ss_list.clear()
    ms_list.clear()
    malformed_list.clear()

    # reseting cli_render class attributes
    cli.clear_lines()
    cli.reset()

    # time delay
    time.sleep(2)

    # increment repetitions
    repetitions += 1

