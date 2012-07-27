#!/bin/sh

OSNAME=`uname -s`
PORT=${1:-80}
PORT2=${2:-7777}

TCPCRYPTD=`dirname $0`/src/tcpcryptd
DIVERT_PORT=666


ee() {
    echo $*
    eval $*
}

linux_set_iptables() {
    echo Tcpcrypting port 80 
    ee iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 666
    
}
linux_unset_iptables() {
    echo Removing iptables rules and quitting tcpcryptd...
    ee iptables -D INPUT  -p tcp --sport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -D OUTPUT -p tcp --dport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -D INPUT  -p tcp --dport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -D INPUT  -p tcp --sport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -D OUTPUT -p tcp --dport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -D OUTPUT -p tcp --sport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    exit
}
check_root() {
    if [ `whoami` != "root" ]
    then
        echo "must be root"
        exit 1
    fi
}

case "$OSNAME" in
    Linux)

        check_root
        linux_set_iptables

        ;;

esac
