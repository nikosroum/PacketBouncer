#!/bin/bash
##########################################################################
# Script for running bouncer applications in course ik2213.
# Note to students: you will have to adapt your application to this script
# The script name must not be changed, neither the parameters.
# Simply ignore unused parameters (such as port numbers in case of "ping").
# In the VMs, the tap interface should _always_ be "tap0".
# Tip: use comand 'export' if you need to set environment variables.
# -----------------------------------------------------------------------
# 2009-05-01 Dan Kopparhed dank@kth.se
##########################################################################
THISFILE=${0##*/}
PID=$$
LISTENIP=$1
LISTENPORT=$2
SERVERIP=$3
SERVERPORT=$4
INTERFACE="tap0"
##########################################################################
fusage()
{
        cat <<USAGETXT
Usage: ${THISFILE} <listen_ip> <listen_port> <server_ip> <server_port>
USAGETXT
}
##########################################################################
fcheckroot()
{
        OUTPUT=`/usr/bin/whoami 2>&1 `
        if [ $OUTPUT != "root" ];then
                echo "Error: you need to be root for this. Aborting."
                exit 1
        fi
}
##########################################################################

if [ $# -lt 4 ];then
        fusage
        exit 1
fi
fcheckroot

#java -Xmx64m -Djava.library.path=/usr/lib64/java Bouncer $INTERFACE $LISTENIP $LISTENPORT $SERVERIP $SERVERPORT
./bouncer $INTERFACE $LISTENIP $LISTENPORT $SERVERIP $SERVERPORT

exit 0
