"""
  File Name: service_mover.py
  Author: Thomas Kreutzer
  Date created: May 18, 2021
  Date last modified: July 20, 2021
  Python Version: 2.7.5
  Description: Applies TLS configurations to Cloudera Manager services and roles
               This is based upon a template existing for each service and template(s)
               existing for each of the role config groups.
 Change Log
  Change Number | Date MM-DD-YYYY  | Changed By        | Change Description
  Initial       | 07-20-2021       | Thomas Kreutzer   | Initial code draft 
  Possible Dependencies for this script.
  pathlib:
      Install with pip:  pip install pathlib
      Manual Download Python 2.7 compatible:
        https://pypi.org/project/pathlib/
  jinja2:
    Manual Download Python 2.7 compatible:
      https://pypi.org/project/Jinja2/2.11.3/#files
  MarkupSafe >= 0.23:
    Manual Download Python 2.7 compatible:
      https://files.pythonhosted.org/packages/c0/41/bae1254e0396c0cc8cf1751cb7d9afc90a602353695af5952530482c963f/MarkupSafe-0.23.tar.gz
      Untar
      pthon setup.py install
"""


from logging import error
import cm_client
from cm_client.rest import ApiException
from pprint import pprint
from jinja2 import Environment
from collections import namedtuple
from datetime import datetime
import os.path
import socket
from pathlib import Path
import logging
import json
import time

logger = logging.getLogger('update_templates')
logger.setLevel(logging.DEBUG)

"""
Cloudera Manager configurations
"""
cm_user = 'admin'
cm_pass = 'admin'
cm_api_version = 'v41'
tls=True
ca_cert_path = '/opt/cloudera/security/pki/rootCA.pem'
cluster_name = 'CDP_cluster_0701_3'
restart_cluster_flag=False


"""
SSL related configurations
NOTE: Cloudera does not support keystores with a different password for the key from the keystore
      https://docs.cloudera.com/documentation/enterprise/6/6.3/topics/how_to_configure_cm_tls.html
"""
cluster_ssl_cert_path = '/opt/cloudera/security/pki/'
cluster_keystore_path = '/opt/cloudera/security/pki/'
cluster_keystore_filename= 'host_keystore.jks'
cluster_truststore_filename='cluster_truststore.jks'
cluster_key_pem_filename='host.key'
cluster_key_pw_filename='key.pwd'
cluster_cert_filename='host.crt'
cluster_ca_cert_filename='rootCA.pem'
keystore_password = 'Cloudera123'
key_password = 'Cloudera123'
truststore_password = 'Cloudera123'

'''
  NOTE: Additional services not included in this list, some will be added later
  "FLINK", "KUDU", "RANGER", "RANGER_KMS"
'''
service_list=["KNOX", "ATLAS", "CRUISE_CONTROL", "HBASE", "HDFS", "HIVE_ON_TEZ", "HIVE", "HUE", "IMPALA", "KAFKA", "LIVY", "OOZIE", "OZONE", "PHOENIX", "QUEUEMANAGER", "SCHEMAREGISTRY", "SOLR", "SPARK_ON_YARN", "STREAMS_MESSAGING_MANAGER", "STREAMS_REPLICATION_MANAGER", "YARN", "ZEPPELIN", "ZOOKEEPER"]

"""
Additional configurations that are required
when executing TLS for a target cluster
"""
kafka_connect_port='28085'
kafka_broker_port='9093'



"""
------------------------------------------------------------------------------------------------------------------
--CONFIGURATION BEYOND THIS LINE SHOULD NOT BE REQUIRED ----------------------------------------------------------
------------------------------------------------------------------------------------------------------------------
"""
kafka_connect_bootstrap_servers=''
streams_replication_manager_config=''
#Service variables
cmd_api_instance=''
cluster_api_instance=''
services_api_instance=''
role_api_instance=''
roles_api_instance=''
mgmtroles_api_instance=''
mgmtroles_config_api_instance=''


class MgmtServices:
    def __init__(self, mgmtroles_api_instance, mgmtroles_config_api_instance):
        self._mgmtroles_api_instance = mgmtroles_api_instance
        self._mgmtroles_config_api_instance = mgmtroles_config_api_instance
        self._keystore_location = cluster_keystore_path + cluster_keystore_filename
        
    def read_mgmt_roles(self):
        try:
            return self._mgmtroles_api_instance.read_roles()
        except ApiException as e:
            print("Exception when calling MgmtRolesResourceApi->read_roles: %s\n" % e)
    
    def apply_mgmt_confg(self, role_config_group_name, body):
        msg = 'Updating parameter(s) for management service {name}'.format(name=role_config_group_name)
        try:
            api_response = self._mgmtroles_config_api_instance.update_config(role_config_group_name, message=msg, body=body)
        except ApiException as e:
            print("Exception when calling MgmtRoleConfigGroupsResourceApi->update_config: %s\n" % e)
            
    def apply_mgmt_tls(self):
        """
        Sets TLS for Service Montior and Hostmonitor, configs should be the same.
        """
        mgmt_roles = self.read_mgmt_roles()
        configs=[]
        configs.append(cm_client.ApiConfig(name='ssl_enabled', value=True))
        configs.append(cm_client.ApiConfig(name='ssl_server_keystore_location', value=self._keystore_location))
        configs.append(cm_client.ApiConfig(name='ssl_server_keystore_password', value=keystore_password))
        for role in mgmt_roles.items:
            if role.type == "SERVICEMONITOR":
                self.apply_mgmt_confg(role.role_config_group_ref.role_config_group_name, cm_client.ApiConfigList(configs))
            elif role.type =="HOSTMONITOR":
                self.apply_mgmt_confg(role.role_config_group_ref.role_config_group_name, cm_client.ApiConfigList(configs))
            elif role.type == "ACTIVITYMONITOR":
                self.apply_mgmt_confg(role.role_config_group_ref.role_config_group_name, cm_client.ApiConfigList(configs))


def setup_api():
    """
    Helper to set up the Cloudera Manager API
    This assumes that you are executing this script on the 
    Cloudera Manager host
    :return: api_client
    """
    cm_host = socket.gethostname()
    cm_client.configuration.username = cm_user
    cm_client.configuration.password = cm_pass
    if tls:
        logging.info('Setting up with TLS true')
        cm_client.configuration.verify_ssl = tls
        cm_client.configuration.ssl_ca_cert = ca_cert_path
        api_host = 'https://{host}'.format(host=cm_host)
        api_url = api_host + ':7183/api/' + cm_api_version
    else:
        logging.info("TLS is not enabled")
        api_host = 'http://{host}'.format(host=cm_host)
        api_url = api_host + ':7180/api/' + cm_api_version
        
    api_client = cm_client.ApiClient(api_url)
    return api_client

def log_properties_change(name, value):
    if "pass" in name:
        logger.info("Setting the property: {name} and the value: {value}".format(name=name, value='REDACTED'))
    else:
        logger.info("Setting the property: {name} and the value: {value}".format(name=name, value=value))

def handle_service_configs(service_configs, service_ref_name):
    configs = []
    for properties in service_configs:
        if properties.has_key('value'):
            log_properties_change(properties['name'], properties['value'])
            configs.append(cm_client.ApiConfig(name=properties['name'], value=properties['value']))
    if len(configs) > 0:
        msg = 'Updating parameter(s) for {service_type}'.format(service_type=service_ref_name)
        try:
            print(msg)
            api_response = services_api_instance.update_service_config(cluster_name=cluster_name, service_name=service_ref_name, message=msg,body=cm_client.ApiConfigList(configs))
            pprint(api_response)
        except ApiException as e:
            print("Exception when calling ServicesResourceApi->update_config: %s\n" % e)
    else:
        print("No Service Configs to update")

def handle_role_configs(role_configs, service_ref_name):
    for rcg in role_configs:
        configs = []
        if rcg.has_key('configs'):
            msg = 'Updating parameter(s) for {service_type} and role config group {rcg}'.format(service_type=service_ref_name, rcg=rcg['refName'])
            for properties in rcg['configs']:
                log_properties_change(properties['name'], properties['value'])
                configs.append(cm_client.ApiConfig(name=properties['name'], value=properties['value']))
            try:
                print(msg)
                body=cm_client.ApiConfigList(configs)
                print(body)
                api_response = role_api_instance.update_config(cluster_name=cluster_name, 
                                                                  role_config_group_name=rcg['refName'],
                                                                  service_name=service_ref_name,
                                                                  message=msg, 
                                                                  body=body)
                pprint(api_response)
            except ApiException as e:
                print("Exception when calling RoleConfigGroupsResourceApi->update_config: %s\n" % e)

def iterate_json(json_str):
    json_data = json.loads(json_str)
    for service in json_data['services']:
        if service.has_key('serviceConfigs'):
            handle_service_configs(service['serviceConfigs'], service['refName'])
        if service.has_key('roleConfigGroups'):
            handle_role_configs(service['roleConfigGroups'],  service['refName'])

def get_role_ref_names():
    services = services_api_instance.read_services(cluster_name, view='FULL')
    for service in services.items:
        api_response = role_api_instance.read_role_config_groups(cluster_name, service.name).to_dict()
        for i in api_response['items']: 
            print(service.type, i['name'])

def read_json(template_path, service_name):
    json_input_file = template_path + '/' + service_name + '.json'
    logger.debug('Checking for existing template: {template}'.format(template=json_input_file))
    input_file = os.path.isfile(json_input_file)
    json_str=''
    if input_file == True:
        with open(json_input_file) as in_file:
            json_str = in_file.read()
    return json_str



def update_service_json(json_str, service_type, service_ref_name, role_config_groups):
    global streams_replication_manager_config
    output = Environment().from_string(json_str).render(service_type=service_type,
                                                        service_ref_name=service_ref_name,
                                                        role_config_groups=role_config_groups,
                                                        cluster_ssl_cert_path=cluster_ssl_cert_path,
                                                        cluster_keystore_path=cluster_keystore_path,
                                                        cluster_keystore_filename=cluster_keystore_filename,
                                                        cluster_truststore_filename=cluster_truststore_filename,
                                                        cluster_key_pem_filename=cluster_key_pem_filename,
                                                        cluster_key_pw_filename=cluster_key_pw_filename,
                                                        cluster_cert_filename=cluster_cert_filename,
                                                        cluster_ca_cert_filename=cluster_ca_cert_filename,
                                                        keystore_password=keystore_password,
                                                        key_password=key_password,
                                                        truststore_password=truststore_password,
                                                        streams_replication_manager_config=streams_replication_manager_config)
    return output

def get_role_config_json(json_str, role_name):
    output = Environment().from_string(json_str).render(ref_name=role_name,
                                                        cluster_ssl_cert_path=cluster_ssl_cert_path,
                                                        cluster_keystore_path=cluster_keystore_path,
                                                        cluster_keystore_filename=cluster_keystore_filename,
                                                        cluster_truststore_filename=cluster_truststore_filename,
                                                        cluster_key_pem_filename=cluster_key_pem_filename,
                                                        cluster_key_pw_filename=cluster_key_pw_filename,
                                                        cluster_cert_filename=cluster_cert_filename,
                                                        cluster_ca_cert_filename=cluster_ca_cert_filename,
                                                        keystore_password=keystore_password,
                                                        key_password=key_password,
                                                        truststore_password=truststore_password,
                                                        kafka_connect_port=kafka_connect_port,
                                                        kafka_connect_bootstrap_servers=kafka_connect_bootstrap_servers)
    return output
    
def update_from_template_list():
    logger.info("Executing update_from_template")
    services = services_api_instance.read_services(cluster_name, view='FULL')
    for service in services.items:
        if service.type in service_list:
            process_service(service)

def process_service(service):
    service_str = read_json("service_templates", service.name)
    #only if the json string is not empty we continue
    if service_str != '':
        final_rcg_str=''
        role_dict = role_api_instance.read_role_config_groups(cluster_name, service.name)
        role_configs=[]
        for role in role_dict.items:
            role_str = read_json("role_config_templates/" + service.name, role.role_type.lower())
            if role_str != '':
                role_str = get_role_config_json(role_str, role.name)
                role_configs.append(role_str)
        if len(role_configs) > 0:
            final_rcg_str=''
            i = 0
            while i < len(role_configs):
                final_rcg_str = final_rcg_str + role_configs[i]
                if i < len(role_configs)-1:
                    final_rcg_str = final_rcg_str + "," #Add comma only when not last object
                final_rcg_str = final_rcg_str + "\n" #Add new line
                i += 1 #increment
        #Update the final service configurations
        service_str = update_service_json(service_str, service.type, service.display_name, final_rcg_str)
        #call process to update variables from the JSON
        iterate_json(service_str)

def deploy_cluster_config():
    cmd = cluster_api_instance.deploy_client_config(cluster_name)
    wait(cmd, 300)
    if cmd.success is not None:
        if not cmd.success:
            raise Exception('Failed to refresh the client configurations')
    else:
        logging.info('While refreshing client configurations cmd.success returned None type')

def restart_cluster():
    cmd = cluster_api_instance.restart_command(cluster_name)
    wait(cmd, 1200)
    if cmd.success is not None:
        if not cmd.success:
            raise Exception('Failed to start the cluster')
    else:
        logging.info('While starting cluster cmd.success returned None type')
            
def wait(cmd, timeout=None):
    SYNCHRONOUS_COMMAND_ID = -1
    if cmd.id == SYNCHRONOUS_COMMAND_ID:
        return cmd
    SLEEP_SECS = 5
    if timeout is None:
        deadline = None
    else:
        deadline = time.time() + timeout
    try:
        
        while True:
            cmd = cmd_api_instance.read_command(long(cmd.id))
            pprint(cmd)
            if not cmd.active:
                return cmd
            if deadline is not None:
                now = time.time()
                if deadline < now:
                    return cmd
                else:
                    time.sleep(min(SLEEP_SECS, deadline - now))
            else:
                time.sleep(SLEEP_SECS)
    except ApiException as e:
        logging.error("Exception reading and waiting for command %s\n" %e)
        
def get_kafka_roles():
    try:
        response = roles_api_instance.read_roles(cluster_name, "kafka", view='summary')
        return response
    except ApiException as e:
        print("Exception when calling RolesResourceApi->read_roles: %s\n" % e)

def get_kafka_hosts():
    kafka_roles = get_kafka_roles()
    kafka_hosts=[]
    for role in kafka_roles.items:
        if role.type == 'KAFKA_BROKER':
            kafka_hosts.append(role.host_ref.hostname)
    return kafka_hosts

def configure_kafka_properties():
    global kafka_connect_bootstrap_servers
    kafka_hosts = get_kafka_hosts()
    kafka_connect_bootstrap_servers='{b1}:{kafka_broker_port},{b2}:{kafka_broker_port},{b3}:{kafka_broker_port}'.format(b1=kafka_hosts[0],b2=kafka_hosts[1],b3=kafka_hosts[2],kafka_broker_port=kafka_broker_port)

def configure_srm_properties():
    global streams_replication_manager_config
    kafka_hosts = get_kafka_hosts()
    streams_replication_manager_config='bootstrap.servers={b1}:{kafka_broker_port}'.format(b1=kafka_hosts[0],kafka_broker_port=kafka_broker_port)

if __name__ == '__main__':
    api_client = setup_api()
    
    #Set up API instances
    cmd_api_instance = cm_client.CommandsResourceApi(api_client)
    cluster_api_instance = cm_client.ClustersResourceApi(api_client)
    services_api_instance = cm_client.ServicesResourceApi(api_client)
    role_api_instance = cm_client.RoleConfigGroupsResourceApi(api_client)
    roles_api_instance = cm_client.RolesResourceApi(api_client)
    mgmtroles_api_instance = cm_client.MgmtRolesResourceApi(api_client)
    mgmtroles_config_api_instance = cm_client.MgmtRoleConfigGroupsResourceApi(api_client)
    
    #get instance of management services class
    mgmt=MgmtServices(mgmtroles_api_instance, mgmtroles_config_api_instance)
    mgmt.apply_mgmt_tls()
    
    
    if "KAFKA" in service_list:
        configure_kafka_properties()
        
    if "STREAMS_REPLICATION_MANAGER" in service_list:
        configure_srm_properties()
    
    update_from_template_list()
    deploy_cluster_config()
    if restart_cluster_flag:
        restart_cluster()

