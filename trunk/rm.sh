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
    ee iptables -I INPUT  -p tcp --sport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I OUTPUT -p tcp --dport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I FORWARD -p tcp -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I FORWARD -p tcp -j NFQUEUE --queue-num $DIVERT_PORT
}

linux_unset_iptables() {
    ee iptables -D FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 666
    ee iptables -D FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 666
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
        linux_unset_iptables
        ;;

esac
