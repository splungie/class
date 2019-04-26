#!/bin/bash

logfwkernel=`hostname`" kernel"
logfile=/var/log/kern.log
logtmp=/root/logtmp
fwtmp=/root/fwtmp
fwrules=/root/fwrules.sh
exclude=".255.255"

hostip=$(cat /etc/hosts | grep `hostname` | awk '{ print $1 }' | sort -u)

scannerhosts="scanner_host_1,scanner_host_2"
scannedhosts="scanned_host_1,scanned_host_2"

rm -f $logtmp
rm -f $fwtmp
rm -f $fwrules

cat "$logfile" | grep "$logfwkernel" | grep -e ".*IN=.*OUT=.*" | egrep -v "SRC=$hostip.*DST=$hostip|SRC=127.0.0.1.*DST=127.0.0.1" | grep -v 0.0.0.0 | grep -v "$exclude" > $logtmp

if [ -s $logtmp ] ; then
  srvports=`netstat -lptun | grep -e [1-9].* | awk '{ print $4 }' | sed -e 's/^.*://g' | sort -u`

  while IFS=$'n' read values ; do
    inval=`echo $values | gawk '{ if (match($0,/IN=(S+)/,m)) print m[0] }' | sed 's/IN=/-i /g'`
    outval=`echo $values | gawk '{ if (match($0,/OUT=(S+)/,m)) print m[0] }' | sed 's/OUT=/-o /g'`
    protoval=`echo $values | gawk '{ if (match($0,/PROTO=[A-Z](S+)/,m)) print m[0] }' | sed 's/PROTO=/-p /g'`
    typeval=`echo $values | gawk '{ if (match($0,/TYPE=(S+)/,m)) print m[0] }' | sed 's/TYPE=/--icmp-type /g'`
    srcval=`echo $values | gawk '{ if (match($0,/SRC=(S+)/,m)) print m[0] }' | sed 's/SRC=/--src /g'`
    dstval=`echo $values | gawk '{ if (match($0,/DST=(S+)/,m)) print m[0] }' | sed 's/DST=/--dst /g'`
    sptval=`echo $values | gawk '{ if (match($0,/SPT=(S+)/,m)) print m[0] }' | sed 's/SPT=//g'`
    dptval=`echo $values | gawk '{ if (match($0,/DPT=(S+)/,m)) print m[0] }' | sed 's/DPT=//g'`

    if [ -n "$inval" ] ; then
      direction="INPUT"
      dstval=""
      if [[ "${srvports[@]}" =~ "$dptval" ]] ; then
        sptval=""
        if [ -n "$dptval" ] ; then
          dptval="--dport "$dptval
        else dptval=""
        fi
      else
        dptval=""
        if [ -n "$sptval" ] ; then
          sptval="--sport "$sptval
        else sptval=""
        fi
      fi
    fi

    if [ -n "$outval" ] ; then
      direction="OUTPUT"
      srcval=""
      if [[ "${srvports[@]}" =~ "$sptval" ]] ; then
        dptval=""
        if [ -n "$sptval" ] ; then
          sptval="--sport "$sptval
        else sptval=""
        fi
      else
        sptval=""
        if [ -n "$dptval" ] ; then
          dptval="--dport "$dptval
        else dptval=""
        fi
      fi
    fi

    if [ -n "$inval" ] && [ -n "$outval" ] ; then
      direction="FORWARD"
      if [ -n "$sptval" ] ; then
        sptval="--sport "$sptval
      else sptval=""
      fi
      if [ -n "$dptval" ] ; then
        dptval="--dport "$dptval
      else dptval=""
      fi
    fi

    if [[ ! "${scannedhosts[@]}" =~ "$srcval" ]] ; then
      echo "iptables -A" $direction $inval $outval $srcval $dstval $protoval $typeval $sptval $dptval "-j ACCEPT"
      echo "iptables -A" $direction $inval $outval $srcval $dstval $protoval $typeval $sptval $dptval "-j ACCEPT" >> $fwtmp
    fi

  done < $logtmp

  echo "#!/bin/bash" > $fwrules

  echo "#Reset firewall:" >> $fwrules
  echo iptables -F >> $fwrules
  echo iptables -P INPUT DROP >> $fwrules
  echo iptables -P OUTPUT DROP >> $fwrules
  echo iptables -P FORWARD DROP >> $fwrules

  echo "#Base rules:" >> $fwrules
  echo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT >> $fwrules
  echo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT >> $fwrules
  echo iptables -A INPUT -i lo --src 127.0.0.1 -j ACCEPT >> $fwrules
  echo iptables -A OUTPUT -o lo --dst 127.0.0.1 -j ACCEPT >> $fwrules
  echo iptables -A INPUT --src $hostip -j ACCEPT >> $fwrules
  echo iptables -A OUTPUT --dst $hostip -j ACCEPT >> $fwrules

  echo "#Enable scanner and scanned hosts:" >> $fwrules

  if [ -n "$scannerhosts" ] ; then
    echo iptables -A INPUT --src $scannerhosts -j ACCEPT >> $fwrules
  fi
  if [ -n "$scannedhosts" ] ; then
    echo iptables -A OUTPUT --dst $scannedhosts -j ACCEPT >> $fwrules
  fi
  if [ -n "$scannerhosts" ] && [ -n "$scannedhosts" ] ; then
      echo iptables -A FORWARD --src $scannerhosts --dst $scannedhosts -j ACCEPT >> $fwrules
  fi

  echo "#Protection des attaques SMURF:" >> $fwrules
  echo iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP >> $fwrules
  echo iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP >> $fwrules
  echo iptables -A INPUT -p icmp -m icmp -m limit --limit 1/second -j ACCEPT >> $fwrules

  echo "#Arret des packets invalides:" >> $fwrules
  echo iptables -A INPUT -m state --state INVALID -j DROP >> $fwrules
  echo iptables -A FORWARD -m state --state INVALID -j DROP >> $fwrules
  echo iptables -A OUTPUT -m state --state INVALID -j DROP >> $fwrules

  echo "#Protection contre attaques RST:" >> $fwrules
  echo iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT >> $fwrules

  echo "#Prevention des portscans. Bloquage de 24 heures (3600 x 24 = 86400 Seconds):" >> $fwrules
  echo iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP >> $fwrules
  echo iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP >> $fwrules

  echo "#Debloquer apres 24 heures:" >> $fwrules
  echo iptables -A INPUT -m recent --name portscan --remove >> $fwrules
  echo iptables -A FORWARD -m recent --name portscan --remove >> $fwrules

  echo "#Ces regles regissent les portscan et les stoppent:" >> $fwrules
  echo iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" >> $fwrules
  echo iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP >> $fwrules
  echo iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" >> $fwrules
  echo iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP >> $fwrules

  echo "#Recognized communications:" >> $fwrules

  cat $fwtmp | sort -u >> $fwrules

  echo "#Other communication (denied) to log:" >> $fwrules
  echo iptables -A INPUT -j LOG >> $fwrules
  echo iptables -A OUTPUT -j LOG >> $fwrules
  echo iptables -A FORWARD -j LOG >> $fwrules
  chmod +x $fwrules

fi

rm -f $logtmp
rm -f $fwtmp
