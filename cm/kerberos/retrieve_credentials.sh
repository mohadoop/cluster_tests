#!/usr/bin/env bash
# set -e
set -x
# Explicitly add RHEL5/6 and SLES11 locations to path
export PATH=/usr/kerberos/sbin:/usr/lib/mit/sbin:/usr/sbin:$PATH
# CMF_REALM=${CMF_PRINCIPAL##*\@}
# Specify the path to a custom script (or executable) to retrieve a Kerberos keytab.
# The script should take two arguments: 
# -     a destination file to write the keytab to, and 
# -     the full principal name to retrieve the key for.


# Cloudera Manager will input a destination path
DEST=$1

# Cloudera Manager will input the principal name in the format: <service>/<fqdn>@REALM
PRINCIPAL=$2


service_name=`echo $PRINCIPAL | cut -d/ -f1`
host_name=`echo $PRINCIPAL | cut -d/ -f2 | cut -d"@" -f1 | cut -d"." -f1`
which_keytab_to_use=${service_name}.${host_name}.keytab
cp /opt/Cloudera/keytabs/${which_keytab_to_use} $DEST
echo PRINCIPAL = $PRINCIPAL DEST = $DEST which_keytab_to_use = $which_keytab_to_use
# touch $KEYTAB_OUT
chmod 600 $DEST