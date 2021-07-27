#/bin/bash

set -eo pipefail

#Backup the original file
sudo cp -p /etc/cloudera-scm-agent/config.ini /etc/cloudera-scm-agent/config.ini.${NOW}


sudo sed -e 's/.*use_tls\=.*/use_tls\=1/' -i /etc/cloudera-scm-agent/config.ini;
sudo sed -e "s/.*verify_cert_file\=.*/verify_cert_file\=\/opt\/cloudera\/security\/pki\/rootCA.pem/" -i /etc/cloudera-scm-agent/config.ini;
sudo sed -e "s/.*client_cert_file\=.*/client_cert_file\=\/opt\/cloudera\/security\/pki\/host.crt/" -i /etc/cloudera-scm-agent/config.ini;
sudo sed -e "s/.*client_key_file\=.*/client_key_file\=\/opt\/cloudera\/security\/pki\/host.key/" -i /etc/cloudera-scm-agent/config.ini;
sudo sed -e "s/.*client_keypw_file\=.*/client_keypw_file\=\/opt\/cloudera\/security\/pki\/key.pwd/" -i /etc/cloudera-scm-agent/config.ini;

echo -n '--Restarting Cloudera Manager agent...';

sudo systemctl restart cloudera-scm-agent;

exit 0
