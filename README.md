# TCP Traceroute
This is a simple implementation of the traceroute tool using TCP SYN packets to trace the path to a target host.

## Features

* Trace the path to a target host using TCP SYN packets.
* Specify the maximum number of hops (-m option).
* Specify the destination port (-p option).
* Display the round-trip time for each hop.

## Requirements

* Linux operating system
* GCC compiler
* libpcap library

## Compilation

Compile the program using the following command:
```
gcc -o tcp_traceroute tcp_traceroute.c -lpcap
```

## Usage 

Run the program with the following command:

```
sudo ./tcp_traceroute -t <target_host> [-m <max_hops>] [-p <destination_port>]
```

* <target_host>: The IP address or hostname of the target host.
* <max_hops>: (Optional) The maximum number of hops to trace. Default is 30.
* <destination_port>: (Optional) The destination port to use for TCP SYN packets. Default is 80.

## Example

Trace the path to example.com on port 80 with a maximum of 20 hops:

```
sudo ./tcp_traceroute -t example.com -m 20 -p 80
```
