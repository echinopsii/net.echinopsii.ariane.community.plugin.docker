#!/bin/bash

case "$1" in
    start)
        if [ "${UID}" = "" ]; then
            UID = `id -u`
        fi
        if [ $UID -ne 0 ]; then
           echo "[WARNING] $0 is not running as root but $USER..."
           echo "[WARNING] It will not be abble to map all docker container processes and connections
            on this OS and may have some problems with the logs..."
        fi
        echo "Starting Ariane Docker"
        python3 -m ariane_docker &
        echo $! > /tmp/adocker.pid
        ;;
    stop)
        if [ -f /tmp/adocker.pid ]; then
            echo "Stopping Ariane Docker"
            cat /tmp/adocker.pid | xargs kill
            rm /tmp/adocker.pid
        else
            echo "Ariane Docker not started..."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

