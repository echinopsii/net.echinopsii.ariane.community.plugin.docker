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
        already_started=`ps -aef | grep 'ariane_docker' | grep -v grep | awk '{print $2}' | wc -l`
        if [ $already_started -eq 1 ]; then
            echo "[ERROR] Ariane Docker plugin is already started on this server."
            exit
        fi
        echo "Starting Ariane Docker"
        exec -a ariane-plg.docker python3 -m ariane_docker > /var/log/ariane/adocker_nohup.log 2>&1 &
        ;;
    stop)
        stopped=`ps -aef | grep 'ariane_docker' | grep -v grep | awk '{print $2}' | wc -l`
        if [ $stopped -eq 1 ]; then
            printf "Stopping Ariane Docker "
            pid=`ps -aef | grep 'ariane_docker' | grep -v grep | awk '{print $2}' `
            kill $pid

            count=0
            stopped=`ps -aef | grep 'ariane_docker' | grep -v grep | awk '{print $2}' | wc -l`
            while [ $stopped -eq 1 ]
            do
                count=`expr $count + 1`
                if [ $count -eq 10 ]; then
                    kill -9 $pid
                fi
                sleep 1
                printf "."
                stopped=`ps -aef | grep 'ariane_docker' | grep -v grep | awk '{print $2}' | wc -l`
            done
            printf "\nAriane Docker is stopped.\n"
        else
            echo "Ariane Docker not started..."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

