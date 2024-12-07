# WhereMyTunnels
This is a python tool to view current ssh connections on linux to help diagnose and keep track when tunneling

![image](https://github.com/user-attachments/assets/d1e57d65-2808-40cf-a13b-e7f1a4b8254a)

## Changelog
### Version 0.4
Version 0.4 is here now written in python. for those wanting the legacy version in bash, it is included in the github legacy folder.

# How it Works

Accurate as of 12/3/2024

## Step 1 Querying SSH Information
The first step is to actually grab the ssh information from the system. This is done via two commands that grab the process information and the socket level information:

```
ps_command = r'ps -ao pid,args -w --no-headers | grep "[s]sh .*" > ' + ps_file
ss_command = r'ss -nap | grep "ssh\"" > ' + ss_file
```

I've included two files that show the sample output [ssh_ps_demo](ssh_ps_demo) and [ssh_ss_demo](ssh_ss_demo)

## Step 1.5 Reading the SSH Information
SSH is very complicated and it would be nearly impossible to write a program that can understand every intracacy of SSH commands. So I went ahead and broke down all ssh commands into a few types for simplicity and organization

| Name | Identifiers | Process Format Example | Socket Format Example | Description |
| - | - | - | - | - |
| Master Socket | `-MS` | `8122 ssh -MS /tmp/test 127.0.0.1` | `u_str LISTEN 0 64 /socket/file.BiD6RlLl7ZqhQS2w 71936` | This is a more advanced method of tunneling that involves creating a socket file that is essentially a portal to another machine. Then you can create socket forwards using the socket file using a second command. |
| Socket Forward | `-S` | `8224 ssh -S /tmp/test test -L 1111:127.0.0.1:22`| `tcp   LISTEN 0 128 127.0.0.1:1111 0.0.0.0:* users:(("ssh",pid=8122,fd=10))` | This is a forward created off of a Master Socket with a specified name. Note: while it is technically a separate process the listening socket PID will be the same as the Master Socket process |
| Traditional Tunnel | `-L`/`-R`/`-D` | `8555 ssh 192.168.1.1 -p 22 -L 5999:192.168.10.1:22` | `tcp   LISTEN 0 128 127.0.0.1:5999 0.0.0.0:* users:(("ssh",pid=8555,fd=5))` | As opposed to a Master Forward this is standalone process that initiates a ssh connection to another machine AND establishes one or more port forwards. Note the socket PID matches the process PID |
| Traditional Session | | `8276 ssh 127.0.0.1 -p 1111` | `tcp ESTAB 0 0 127.0.0.1:45040 127.0.0.1:1111 users:(("ssh",pid=8276,fd=3))` | This is your run-of-the-mil ssh connection |

A few other important considerations:
- There are situations where a process is present but no matching socket information exists. This is how we detect malformed session
- Unfortunately socket forwards and traditional forwards do not show the destination port, because of this we must enumerate it from the process information
- You can determine the type of ssh connection at the socket layer using the `fd=X` however it is more reliable to corroborate the PID, source port, and socket type with the process

## Step 2 Organizing Process File
The next step of the program is to organize the process file. This is done by creating a dictionary and adding it to the ps_list. In the event that the categorization fails due to any error, that line is ignored and added to the malformed_list.

We will briefly go over the difference in each dictionary by the type of connection, however to get the clearest picture you should look at the python code:

### Master Sockets
```
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
```
### Socket Forward
```
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
```
### Traditional Tunnel
```
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
```
### Regular Sessions
```
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
```

## Step 3 Organizing Socket File
Once again we will only go over the differences in the dictionary, more information can be found in the source code.

### Master Sockets
```
out_socket = {
    "org_num" : 0,
    "pid" : pid,
    "type" : socket_type,
    "socket_file" : socket_file,
    "socket_code" : socket_code,
}
ss_list.append(out_socket)
```

### Socket Forwards, Traditional Tunnels, and Regular Sessions
Because their formatting is so similar these all use the same dictionary format.
```
out_socket = {
    "org_num" : 0,
    "pid" : pid,
    "type" : socket_type,
    "src_ip" : src_ip,
    "src_port" : src_port,
    "dest_ip" : dest_ip,
    "dest_port" : dest_port, # note this may be "*" since listening ports do not have a specified destination
}
if debug : print("Creating Socket: [{}]".format(out_socket))
ss_list.append(out_socket)
```

## Step 4 Building the Master List
Now that we have built the process list and socket list we need to combine them to match processes with their corresponding socket entries.

### Master Sockets, Socket Forwards, and Associated Sessions
What we are trying to do is build a tree for each master socket like so:
```
Master Socket
\-- Socket Forward Process
    \-- Individual Forward
        \-- Associated Sessions (these indicate that the particular forward is being used)
    \-- Individual Forward
\-- Associated Sessions (these are to maintain the master socket)
```

To do this we start by find unsorted master sockets using the `type` field as well as the `org_num` field to verify we haven't already sorted it:
```
for master_process in ps_list:
    if master_process["org_num"] == 0 and master_process["type"] == "MS":
```

We then attempt to grab the associated socket. If none is found we add the item to the malformed list and mark the `org_num` to `-2`. An additional check is done to verify the `socket_file` in the process and socket match

```
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
```

Once we've done this we can create the master_entry dictionary
```
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
```
#### Attaching Forwards
Now that we have a Master Socket Master Entry (thats a mouthful) we need to find any associated socket forwards.

This is done in a few steps

##### Sub-Step 1 Finding Matching Processes
We start by find any process that has:
- `org_num` is 0 (meaning it is unsorted)
- `type` is `"S"` or Socket Forward
- `socket_file` matches the master socket's `socket_file`

##### Sub-Step 2 Finding Matching Sockets
For each of the processes found in the previous step we go through their forwards and attempt them to match them with entries in the `ss_list` that have:
- `org_num` is 0 (meaning it is unsorted)
- `type` is `"tcpLISTEN"`
- `pid` matches master socket `pid`
- `src_port` on socket and process match

If all of these are true, then a chid_entry is added to the master_entry
```
child_entry = {
    "org_num" : 0,
    "pid" : child_process["pid"],
    "type" : "S_FWD",
    "process" : child_process
}
master_entry["attached"].append(child_entry)
```

#### Attaching Sessions
This is a lot simpler since we just find any socket with a matching pid and `"tcpESTAB"` and create a child_entry that is then added to the master_entry:

```
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
```

If we find any type matching `"u_strESTAB"` we ignore it.
```
elif child_socket["type"] == "u_strESTAB":
    child_socket["org_num"] = -1 # mark as ignored
```

### Organizing Traditional Forwards
This is WAYYY simpler than Master Sockets since there is one program for the tunnels instead of a master socket and a forward process. The tree ends up looking something like this:
```
Tradition Tunnel
\-- Forward
    \-- Associated Sessions (these indicate that the particular forward is being used)
\-- Associated Sessions (these are to maintain the traditional tunnel)
```

The interesting thing about traditional forwards is that there is no "main" socket entry, unlike master sockets where there is a main "u_strLISTEN" line. This means that we have one process and several "tcpLISTEN" (forwards) and "tcpESTAB" (sessions) that all share the one process.

We start by finding the traditional tunnels by looking for `type` of `"TD"` and a `org_num` of 0. Once we find this we proceed with creating an entry in the master list:

```
entry = {
    "org_num" : 0,
    "pid" : process["pid"],
    "type" : "TD",
    "process" : process,
    "attached" : []
}
ms_list.append(entry)
```

#### Attaching Forwards
We start by iterating through all of the `forwards` in the traditional tunnel, then for each forward we attempt to match them with sockets that meet the following criteria:

- `org_num` is 0
- `type` is `"tcpLISTEN"` (forward)
- `pid` and `src_port` matches between the `entry` (see above) and the socket

if these match we add the socket to `forward_process["socket"]`:

```
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
```

#### Attaching Sessions
This is really simple, we find sockets with a matching `pid`, `org_num` of 0, and a `type` of `"tcpESTAB"`. They are then used to create the following dictionary:

```
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
```
#### Adding Regular Entries
This is pretty simple, find any remaining socket entry with a `type` of `"tcpESTAB"`, find it's associated process by matchin PIDs, then add it to the master list using the following dictionary entry:

```
# build ms_list entry
ssh_entry = {
    "org_num" : 0,
    "pid" : socket["pid"],
    "type" : "SH",
    "process" : process,
    "socket" : socket
}
ms_list.append(ssh_entry)
```

## Step 5 Making it Look Pretty
So we have successfully organized everything into the master list, now we work to print out the master list in a semi-coherrent format.

I'm not going to go over the code in-depth here, instead I will give a simpler pseudo code explanation.

Formatting:
```
Print Master Socket Title
    Print Master Sockets (process + socket)
        Print Forwards (process)
            Print Sessions (socket) - Note a check for matching src_port is done to see if sessions are tied to a forward
        Print Associated Sessions (socket) - For sessions that cannot be tied to a forwards but are tied to the master socket

Print Traditional Tunnel Title
    Print Tradition Tunnel (process)
        Print Forwards (Socket)
            Print Associated Sessions (socket) -  Note a check for matching src_port is done to see if sessions are tied to a forward
        Print Associated Sessions (socket) - For sessions that cannot be tied to a forward

Print Regular Sessions Title
    Print Sessions (process + socket)

Print Malformed Sessions
    Print Sessions
```

Note: a tag of "MALFORMED" may be added to forwards that have a process but no associated `"tcpLISTEN"` socket