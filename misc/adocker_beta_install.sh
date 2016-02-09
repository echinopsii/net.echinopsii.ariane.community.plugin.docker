#!/bin/bash

if [ "$UID" = "" ]; then
    UID = `id -u`
fi

if [ ${UID} -ne 0 ]; then
   echo "$0 must be run as root... Exit."
   exit 1
fi

which pip3 > /dev/null
if [ $? -ne 0 ]; then
    echo "$0 needs python 3 and pip3... Exit."
    exit 1
fi

which curl > /dev/null
if [ $? -ne 0 ]; then
    echo "$0 needs curl... Exit."
    exit 1
fi

#which easy_install-3.3 > /dev/null
#if [ $? -ne 0 ]; then
#    which easy_install-3.4 > /dev/null
#    if [ $? -ne 0 ]; then
#        which easy_install-3.5 > /dev/null
#        if [ $? -ne 0 ]; then
#            echo "$0 needs easy_install-3.3|3.4|3.5"
#            exit 1
#        else
#            EASY_INSTALL=`which easy_instal-3.5`
#        fi
#    else
#        EASY_INSTALL=`which easy_install-3.4`
#    fi
#else
#    EASY_INSTALL=`which easy_install-3.3`
#fi

#curl -L https://pypi.python.org/packages/3.3/n/netifaces-merged/netifaces_merged-0.9.0-py3.3-linux-x86_64.egg#md5=269c66235a25e83509b0cbdc2dab28e9 > /tmp/netifaces.egg
#$EASY_INSTALL /tmp/netifaces.egg

which apt-get > /dev/null
if [ $? -ne 0 ]; then
    which rpm > /dev/null
    if [ $? -ne 0 ]; then
        echo "apt-get nor rpm not found. Your OS is not supported !"
    else
        yum install gcc python3-devel -y > /dev/null
    fi
else
    apt-get install gcc python3-dev -y > /dev/null
fi

pip3 uninstall ariane_docker -y > /dev/null
pip3 install --pre ariane_docker > /dev/null
if [ $? -ne 0 ]; then
    pip3 install --pre ariane_docker
    echo "Problems while installing Ariane Docker python module... Exit."
    exit 1
fi

if [ ! -d /etc/ariane ]; then
    mkdir /etc/ariane
fi

if [ ! -d /var/log/ariane ]; then
    mkdir /var/log/ariane
fi

curl -L https://raw.githubusercontent.com/echinopsii/net.echinopsii.ariane.community.plugin.docker/master/misc/adocker_configuration.json > /etc/ariane/adocker_configuration.json
curl -L https://raw.githubusercontent.com/echinopsii/net.echinopsii.ariane.community.plugin.docker/master/misc/adocker_logging.json > /etc/ariane/adocker_logging.json
curl -L https://raw.githubusercontent.com/echinopsii/net.echinopsii.ariane.community.plugin.docker/master/misc/adocker.sh > /usr/local/bin/adocker
chmod 755 /usr/local/bin/adocker

echo ""
echo "Ariane Docker successfully installed on this operating system..."
echo "Take time to define Ariane server connections and describe this operating system context by editing /etc/ariane/adocker_configuration.json..."
echo "Then you can start mapping your Docker components by starting Ariane Docker this way : /usr/local/bin/adocker start"