#!/bin/bash

# Install dependencies
apt update
apt --yes install \
    git \
    supervisor \
    build-essential \
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libev-dev \
    libglib2.0-dev \
    libloudmouth1-dev \
    libnetfilter-queue-dev \
    libnl-3-dev \
    libpcap-dev \
    libssl-dev \
    libtool \
    libudns-dev \
    python3 \
    python3-dev \
    python3-bson \
    python3-yaml \
    python3-boto3 

# Clone Dionaea from Github
git clone https://github.com/DinoTools/dionaea.git 
cd dionaea

# Latest tested version with this install script
git checkout baf25d6

mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..

make
make install


# Add and configure HPFeeds
while true; do
    read -p "Do you want to intergarte MHN / hpfeeds? (Y/N)" yn
    case $yn in
        [Yy]* ) echo -n "Enter your server hostname or IP and press [ENTER]: "
                read HPF_HOST
                echo -n "Enter your PORT and press [ENTER]: "
                read HPF_PORT
                echo -n "Enter your MHN Identity and press [ENTER]: "
                read HPF_IDENT
                echo -n "Enter your MHN Secret and press [ENTER]: "
                read HPF_SECRET
                cat > /opt/dionaea/etc/dionaea/ihandlers-enabled/hpfeeds.yaml <<EOF
- name: hpfeeds
    config:
    # fqdn/ip and port of the hpfeeds broker
    server: "$HPF_HOST"
    # port: $HPF_PORT
    ident: "$HPF_IDENT"
    secret: "$HPF_SECRET"
    # dynip_resolve: enable to lookup the sensor ip through a webservice
    dynip_resolve: "http://canhazip.com/"
    # Try to reconnect after N seconds if disconnected from hpfeeds broker
    # reconnect_timeout: 10.0
EOF
                break;;

        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Add and configure Virustotal
while true; do
    read -p "Do you want to intergarte VirusTotal (You will need a VirusTotal API Key) (Y/N)?" yn
    case $yn in
        [Yy]* ) echo -n "Enter your VirusTotal API Key and press [ENTER]: "
                read VirusTotal_Key
                cat > /opt/dionaea/etc/dionaea/ihandlers-enabled/virustotal.yaml <<EOF
- name: virustotal
  config:
    # grab it from your virustotal account at My account -> My API Key (https://www.virustotal.com/en/user/<username>/apikey/)
    apikey: "$VirusTotal_Key"
    file: "@DIONAEA_STATEDIR@/vtcache.sqlite"
    comment: "This sample was captured in the wild and uploaded by the dionaea honeypot & Cyber Bytes.\n#honeypot #malware #networkworm #CyberBytes"
EOF
                break;;

        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Add and Configure Incedent Logs
while true; do
    read -p "Do you want to output Dionaea Incedent Log (This is in pre-alpha state) (Y/N)?" yn
    case $yn in
        [Yy]* ) cat > /opt/dionaea/etc/dionaea/ihandlers-enabled/log_incident.yaml <<EOF
- name: log_incident
    config:
        handlers:
            #- http://127.0.0.1:8080/
            - file://@DIONAEA_STATEDIR@/dionaea_incident.json
EOF
echo "These logs will be found in /opt/dionaea/var/lib/dionaea/dionaea_incident.json"
break;;

        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done


#Add and Configure Json Logs
while true; do
    read -p "Do you want to output Dionaea to json Log, this can be ingested into ELK and SPLUNK? (Y/N)" yn
    case $yn in
        [Yy]* ) cat > /opt/dionaea/etc/dionaea/ihandlers-enabled/log_json.yaml <<EOF
- name: log_json
  config:
    # Uncomment next line to flatten object lists to work with ELK
    # flat_data: true
    handlers:
      #- http://127.0.0.1:8080/
      - file://@DIONAEA_STATEDIR@/dionaea.json
EOF
echo "These logs will be found in /opt/dionaea/var/lib/dionaea/dionaea_incident.json"
break;;

        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Add Bistreamns Managment
while true; do
    read -p "Do you want to implement Bistreams rotation?(Y/N)" yn
    case $yn in
        [Yy]* )
            PS3='Select an option and press Enter: '
            options=("Compress Anything Older than 3 hours and Delete Older than 6" "Compress Anything Older than 6 hours and Delete Older than 12" "Compress Anything Older than 12 hours and Delete Older than 24")
                select opt in "${options[@]}"
                    do
                      case $opt in
                            "Compress Anything Older than 3 hours and Delete Older than 6")
                              git clone https://github.com/izm1chael/Dionaea-Bistream-Rotation.git
                              cd Dionaea-Bistream-Rotation
                              mkdir /opt/scripts
                              cp bistreams-rot-3-6.sh /opt/scripts
                              crontab -l | { cat; echo "0 */3 * * * /bin/bash /opt/scripts/bistreams-rot-3-6.sh"; } | crontab -
                              break
                              ;;
                            "Compress Anything Older than 6 hours and Delete Older than 12")
                              git clone https://github.com/izm1chael/Dionaea-Bistream-Rotation.git
                              cd Dionaea-Bistream-Rotation
                              mkdir /opt/scripts
                              cp bistreams-rot-6-12.sh /opt/scripts
                              crontab -l | { cat; echo "0 */6 * * * /bin/bash /opt/scripts/bistreams-rot-6-12.sh"; } | crontab -
                              break
                              ;;
                            "Compress Anything Older than 12 hours and Delete Older than 24")
                              git clone https://github.com/izm1chael/Dionaea-Bistream-Rotation.git
                              cd Dionaea-Bistream-Rotation
                              mkdir /opt/scripts
                              cp bistreams-rot-12-24.sh /opt/scripts
                              crontab -l | { cat; echo "0 */12 * * * /bin/bash /opt/scripts/bistreams-rot-12-24.sh"; } | crontab -
                              break
                              ;;
                            *) echo "invalid option";;
                        esac
                    done
                ;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done


# Dionaea Logging is very heavy, this config will stop that
cat > /opt/dionaea/etc/dionaea/dionaea.cfg <<EOF
[dionaea]
download.dir=var/lib/dionaea/binaries/
modules=curl,python,nfq,emu,pcap
processors=filter_streamdumper,filter_emu

listen.mode=getifaddrs
# listen.addresses=127.0.0.1
# listen.interfaces=eth0,tap0

# Use IPv4 mapped IPv6 addresses
# It is not recommended to use this feature, try to use nativ IPv4 and IPv6 adresses
# Valid values: true|false
# listen.use_ipv4_mapped_ipv6=false

# Country
# ssl.default.c=GB
# Common Name/domain name
# ssl.default.cn=
# Organization
# ssl.default.o=
# Organizational Unit
# ssl.default.ou=

[logging]
default.filename=var/log/dionaea/dionaea.log
default.levels=error
default.domains=*

errors.filename=var/log/dionaea/dionaea-errors.log
errors.levels=error
errors.domains=*

[processor.filter_emu]
name=filter
config.allow.0.protocols=smbd,epmapper,nfqmirrord,mssqld
next=emu

[processor.filter_streamdumper]
name=filter
config.allow.0.types=accept
config.allow.1.types=connect
config.allow.1.protocols=ftpctrl
config.deny.0.protocols=ftpdata,ftpdatacon,xmppclient
next=streamdumper

[processor.streamdumper]
name=streamdumper
config.path=var/lib/dionaea/bistreams/%Y-%m-%d/

[processor.emu]
name=emu
config.limits.files=3
#512 * 1024
config.limits.filesize=524288
config.limits.sockets=3
config.limits.sustain=120
config.limits.idle=30
config.limits.listen=30
config.limits.cpu=120
#// 1024 * 1024 * 1024
config.limits.steps=1073741824

[module.nfq]
queue=2

[module.nl]
# set to yes in case you are interested in the mac address  of the remote (only works for lan)
lookup_ethernet_addr=no

[module.python]
imports=dionaea.log,dionaea.services,dionaea.ihandlers
sys_paths=default
service_configs=etc/dionaea/services-enabled/*.yaml
ihandler_configs=etc/dionaea/ihandlers-enabled/*.yaml

[module.pcap]
any.interface=any
EOF

# Editing configuration for Dionaea.
mkdir -p /opt/dionaea/var/log/dionaea/log
chown -R nobody:nogroup /opt/dionaea/var/log/dionaea

mkdir -p /opt/dionaea/var/log/dionaea/bistreams 
chown nobody:nogroup /opt/dionaea/var/log/dionaea/bistreams

# Config for supervisor.
cat > /etc/supervisor/conf.d/dionaea.conf <<EOF
[program:dionaea]
command=/opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg
directory=/opt/dionaea/
stdout_logfile=/opt/dionaea/var/log/dionaea.out
stderr_logfile=/opt/dionaea/var/log/dionaea.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF






supervisorctl update

supervisorctl start dionaea

echo "[`date`] Completed Installation of Dionaea"

