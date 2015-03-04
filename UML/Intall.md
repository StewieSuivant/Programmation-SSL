# INSTALL

## Configurer Hostname

* modifier le fichier "/etc/hostname" (fail -> nom voulu)
* modifier le fichier "/etc/hosts"  (localhost -> nom voulu)
* /etc/init.d/hostname.sh start
* Le nom est pris en compte au rédémarrage des machines

## Configurer IP

* modifier le fichier "/etc/network/interfaces"
* Oscar :
  * eth0 192.168.0.1/24
  * eth1 172.16.0.1/24
* Alice :
  * eth0 192.168.0.2/24
  * gw : 192.168.0.1
* Bob :
  * eth0 172.16.0.2/24
  * gw : 172.16.0.1

## Routage 

* Oscar : echo 1 > /proc/sys/net/ipv4/ip_forward


## Script au démarrage

* créer un script
* créer un fichier dans init.d de la forme suivantes :
\#!/bin/bash

source /etc/sysconfig/rc
source $rc_functions
case "$1" in
	start)
		echo "Starting lescript..."
		loadproc "chemin script"
		;;
	stop)
		echo "Stopping lescript..."
		killproc "chemin script"
		;;
	reload)
		echo "Reloading lescript..."
		killall -HUP "lescript"
		;;
	restart)
		$0 stop
		sleep 1
		$0 start
		;;
	status)
		statusproc "chemin script"
		;;
	*)
		echo "Usage: $0 {start|stop|reload|restart|status}"
		exit 1
		;;
esac

* update-rc.d script defaults
