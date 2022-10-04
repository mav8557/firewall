# firewall
application firewall for linux


## How it Works

1. Packets are checked in map by destination, source, source port, and dest port and if not found blocked by tc program
2. Outgoing connections are sent to userspace with PID and outbound IP/port/protocol (perf map)
3. Userspace program waits for prompt
4. User optionally responds yes to prompt
5. Map updated and packets are now allowed through
6. When processes are started, set path and PID in map



