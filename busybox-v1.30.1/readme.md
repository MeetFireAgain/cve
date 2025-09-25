# Bug Report 

## Affected Software
- **Product: Busybox** 
- **Version(s): v1.30.1(ubuntu 1:1.30.1 -7ubuntu3.1)** 
- **Vender:Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04**

## Vulnerability Type
NULL Pointer Dereference

## Description
During the parameter parsing process of BusyBox wget, when using the -T option, a NULL pointer dereference exists in the getopt32 function, causing the program to crash.

## Proof of Concept (PoC)
```bash
busybox wget -T 0
```

## Steps to Reproduce
1. Install busybox with this command : sudo apt install busybox
2. run with the poc command,you will see the crash!

## Impact
* Local Denial of Service: Local users can crash BusyBox wget
* Remote Denial of Service: In environments where wget commands are constructed from user input
* Embedded Device Impact: Particularly concerning for IoT and embedded systems using BusyBox
