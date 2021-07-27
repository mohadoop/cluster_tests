import os, sys, stat
import time
import socket
import logging
import cm_client
import hashlib
from cm_client.rest import ApiException
from pprint import pprint


logger = logging.getLogger('kerberize_cluster')
logger.setLevel(logging.DEBUG)

api_version = 'v41'
cm_user = 'admin'
cm_pass = 'admin'
tls=True
cluster_name='CDP_cluster_0701_3'
kdc_type = 'MIT KDC'
krb_realm = 'EXAMPLE.COM'
krb_ingestion_script = '/root/retrieve_credentials.sh'
krb_ticket_lifetime = '86400'
krb_renew_lifetime = '604800'
krb_enc_types = 'aes256-cts'
krb_forwardable = 'true'
krb_manage_krb5_conf = 'false'

##Cloudera ca_cert_path from AutoTLS
ca_cert_path = '/var/lib/cloudera-scm-agent/agent-cert/cm-auto-global_cacerts.pem'

#Api Instance Variables, empty string for default
cm_api_instance=''
cluster_api_instance=''
cmd_api_instance=''
mngmt_api_instance=''
mngmt_rl_cfg_grp_api_instance=''
service_api_instance=''
roles_api_instance=''
role_config_instance=''
host_api_instance=''

#Default global arrays
api_role_name_list=[]

class ActiveCommands:
    def wait(self, cmd, timeout=None):
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

class ApiConfigurationSetup:
    def __init__(self, username, password, tls, ca_cert_path):
        self._username = username
        self._password = password
        self._tls = tls
        self._ca_cert_path = ca_cert_path
    
    def setup_api(self):
        """
        Helper to set up the Cloudera Manager API
        This assumes that you are executing this script on the 
        Cloudera Manager host
        :param str username:
        :param str password:
        :param boolean tls:
        :param str ca_cert_path:
        :return: api_client
        """
        cm_host = socket.gethostname()
        cm_client.configuration.username = self._username
        cm_client.configuration.password = self._password
        if tls:
            logging.info('Setting up with TLS true')
            cm_client.configuration.verify_ssl = self._tls
            cm_client.configuration.ssl_ca_cert = self._ca_cert_path
            api_host = 'https://{host}'.format(host=cm_host)
            api_url = api_host + ':7183/api/' + api_version
        else:
            logging.info("TLS is not enabled")
            api_host = 'http://{host}'.format(host=cm_host)
            api_url = api_host + ':7180/api/' + api_version
            
        api_client = cm_client.ApiClient(api_url)
        return api_client
    
    def validate_krb_ingest_script(self):
        """
        Validate that the KRB ingestion script is available and able to be accessed
        on the Cloudera Manager server.
        """
        if not os.path.isfile(krb_ingestion_script) and not os.access(krb_ingestion_script, os.R_OK):
            raise Exception('KRB ingestion script not available for reading from: ' + krb_ingestion_script)
        #os.chmod(krb_ingestion_script, stat.S_IEXEC)

class Kerberos:
    def __init__(self):
        self._ac = ActiveCommands()
        self._service = Service()
        self._role = Role()
        self._host = Host()
        
    def setup_cm_kerberos(self):
        """
        Sets up the parameters required for Cloudera Manager to be ready to 
        Kerberize the cluster.
        """
        configs = []
        configs.append(cm_client.ApiConfig(name='KDC_TYPE', value=kdc_type))
        configs.append(cm_client.ApiConfig(name='SECURITY_REALM', value=krb_realm))
        configs.append(cm_client.ApiConfig(name='GEN_KEYTAB_SCRIPT', value=krb_ingestion_script))
        configs.append(cm_client.ApiConfig(name='KRB_TICKET_LIFETIME', value=krb_ticket_lifetime))
        configs.append(cm_client.ApiConfig(name='KRB_RENEW_LIFETIME', value=krb_renew_lifetime))
        configs.append(cm_client.ApiConfig(name='KRB_ENC_TYPES', value=krb_enc_types))
        configs.append(cm_client.ApiConfig(name='KRB_FORWARDABLE', value=krb_forwardable))
        configs.append(cm_client.ApiConfig(name='KRB_MANAGE_KRB5_CONF', value=krb_manage_krb5_conf))
        message = 'Updating Cloudera Manager with Kerberos configurations'
        try: # Update the Cloudera Manager settings.
            api_response = cm_api_instance.update_config(message=message, body=cm_client.ApiConfigList(configs))
        except ApiException as e:
            logging.error("Exception when calling ClouderaManagerResourceApi->update_config: %s\n" % e)
    
    def generate_credentials(self):
        cmd = cm_api_instance.generate_credentials_command()
        self._ac.wait(cmd, 120)
        if not cmd.success:
            raise Exception('Failed to generate KRB credentials')
    
    def apply_kerberos_service_configs(self):
        """
        Sets up configurations for each service if it is installed to ensure
        that Kerberos is configured. 
        If any services are missing for Kerberos configurations add them here.
        """
        #Get a list of services, iterate through the services and apply configurations.
        services=''
        try:
            services = service_api_instance.read_services(cluster_name, view='summary')
        except ApiException as e:
            print("Exception when calling ServicesResourceApi->read_services: %s\n" % e)
        for service in services.items:
            if service.type == 'HDFS':
                #Handle service configuration changes for HDFS
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='hadoop_security_authentication', value='kerberos'))
                service_configs.append(cm_client.ApiConfig(name='hadoop_security_authorization', value=True))
                service_configs.append(cm_client.ApiConfig(name='service_config_suppression_hadoop_secure_web_ui', value=True))
                #Other variables I found in my cluster that were not being set, should I set? 
                #{"name": "dfs_encrypt_data_transfer_algorithm", "value": "AES/CTR/NoPadding"}, 
                
                self._service.handle_service_configs(service_configs, service.name)
                
                '''
                Handle role configuration changes for HDFS Datanodes role config groups
                NOTE: We want to query the api for the roles and create a unique list of the
                roleConfigGroupRef.roleConfigGroupName where DATANODE is found.
                '''
                rcg_arr=[] #Array of role config groups
                roles = roles_api_instance.read_roles(cluster_name, service.name, filter='type==DATANODE', view='summary')
                for role in roles.items:
                    if 'DATANODE' in role.role_config_group_ref.role_config_group_name:
                        if role.role_config_group_ref.role_config_group_name not in rcg_arr:
                            rcg_arr.append(role.role_config_group_ref.role_config_group_name)
                #Create the configurations and apply them
                role_config=[]
                role_config.append(cm_client.ApiConfig(name='dfs_datanode_http_port', value='1006'))
                role_config.append(cm_client.ApiConfig(name='dfs_datanode_port', value='1004'))
                role_config.append(cm_client.ApiConfig(name='dfs_datanode_data_dir_perm', value='700'))
                for rcg in rcg_arr:
                    self._role.handle_role_configs(role_config, service.name, rcg)
                
            elif service.type == 'ZOOKEEPER':
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='enableSecurity', value=True))
                service_configs.append(cm_client.ApiConfig(name='quorum_auth_enable_sasl', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == 'YARN':
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='service_config_suppression_hadoop_secure_web_ui', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == 'HBASE':
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='hbase_security_authentication', value='kerberos'))
                service_configs.append(cm_client.ApiConfig(name='hbase_security_authorization', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == 'HUE':
                roles = roles_api_instance.read_roles(cluster_name, service.name, view='summary')
                for role in roles.items:
                    if 'server' in role.name.lower():
                        hostname = role.host_ref.hostname
                        host_id = role.host_ref.host_id
                        ip_address = self._host.get_ip_address(host_id)
                        
                        new_role_type = 'KT_RENEWER'
                        new_role_name = '-'.join([service.name, new_role_type, hashlib.md5(hostname).hexdigest()])[:64]
                        
                        api_role = cm_client.ApiRole(name=new_role_name, type=new_role_type, host_ref=role.host_ref, service_ref=role.service_ref)
                        api_role_list = cm_client.ApiRoleList([api_role])
                        self._role.create_role(api_role_list, service.name)
            elif service.type == "KUDU":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='enable_security', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "ATLAS":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enable', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "OZONE":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='ozone.security.enabled', value=True))
                service_configs.append(cm_client.ApiConfig(name='ozone.security.http.kerberos.enabled', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "SCHEMAREGISTRY":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enable', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "STREAMS_MESSAGING_MANAGER":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enable', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "ZEPPELIN":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='zeppelin.authentication.method.kerberos', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "QUEUEMANAGER":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enabled', value=True))
                #Looks like this may only work on newer version of Cloudera Manager, commenting out for now
                #service_configs.append(cm_client.ApiConfig(name='kerberos_princ_name', value='yarn'))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "STREAMS_REPLICATION_MANAGER":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enable', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "KAFKA":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enable', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "KNOX":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enabled', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "FLINK":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enabled', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "SQL_STREAM_BUILDER":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='security.kerberos.enabled', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "NIFI":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enabled', value=True))
                self._service.handle_service_configs(service_configs, service.name)
            elif service.type == "NIFIREGISTRY":
                service_configs=[]
                service_configs.append(cm_client.ApiConfig(name='kerberos.auth.enabled', value=True))
                self._service.handle_service_configs(service_configs, service.name)

class Service:
    def handle_service_configs(self, configs, service_ref_name):
        if len(configs) > 0:
            msg = 'Updating parameter(s) for {service_type}'.format(service_type=service_ref_name)
            try:
                api_response = service_api_instance.update_service_config(cluster_name=cluster_name, service_name=service_ref_name, message=msg,body=cm_client.ApiConfigList(configs))
            except ApiException as e:
                print("Exception when calling ServicesResourceApi->update_config: %s\n" % e)
        else:
            print("No Service Configs to update")

class Role:
    def handle_role_configs(self, configs, service_ref_name, role_reference_name):
        msg = 'Updating parameter(s) for {service_type} and role config group {rcg}'.format(service_type=service_ref_name, rcg=role_reference_name)
        try:
            print(msg)
            api_response = role_config_instance.update_config(cluster_name=cluster_name,
                                                            role_config_group_name=role_reference_name,
                                                            service_name=service_ref_name,
                                                            message=msg, 
                                                            body=cm_client.ApiConfigList(configs))
        except ApiException as e:
            print("Exception when calling RoleConfigGroupsResourceApi->update_config: %s\n" % e)
            
    def create_role(self, api_role_list, service_name):
        roles_api_instance
        try:
            api_response = roles_api_instance.create_roles(cluster_name, service_name, body=api_role_list)
        except ApiException as e:
            print("Exception when calling RolesResourceApi->create_roles: %s\n" % e)

class Cluster:
    def __init__(self):
        self._ac = ActiveCommands()
    
    def stop(self):
        cmd = cluster_api_instance.stop_command(cluster_name)
        self._ac.wait(cmd, 600)
        if cmd.success is not None:
            if not cmd.success:
                if 'Command unavailable because no services were found matching the request in cluster' in cmd.result_message:
                    logging.info('The cluster does not have any services to stop and this action will be ignored')
                else:
                    raise Exception('Failed to stop the cluster')
        else:
            logging.info('While stopping cluster cmd.success returned None type')
    
    def start(self):
        cmd = cluster_api_instance.start_command(cluster_name)
        self._ac.wait(cmd, 1200)
        if cmd.success is not None:
            if not cmd.success:
                raise Exception('Failed to start the cluster')
        else:
            logging.info('While starting cluster cmd.success returned None type')
            
    def deploy_cluster_config(self):
        cmd = cluster_api_instance.deploy_client_config(cluster_name)
        self._ac.wait(cmd, 300)
        if cmd.success is not None:
            if not cmd.success:
                raise Exception('Failed to refresh the client configurations')
        else:
            logging.info('While refreshing client configurations cmd.success returned None type')

class Host:
    def get_ip_address(self, host_id):
        try:
            host_data = host_api_instance.read_host(host_id)
            return host_data.ip_address
        except ApiException as e:
            print("Exception when calling HostsResourceApi->read_host: %s\n" % e)
    
class MngmtServices:
    def __init__(self):
        self._ac = ActiveCommands()
        
    
    def build_api_role_list(self, rcg_name):
        """
        Build API Role Name List based on role
        :return:
        """
        global api_role_name_list
        api_role_name_list = []
        api_role_list = mngmt_rl_cfg_grp_api_instance.read_roles(rcg_name).items
        for list_item in api_role_list:
            api_role_name = list_item.name
            logging.debug('api_role_name : %s' % api_role_name)
            api_role_name_list.append(api_role_name)
    
    def stop(self):
        global api_role_name_list
        #Read all of the existing installed management role config groups
        role_config_groups = mngmt_rl_cfg_grp_api_instance.read_role_config_groups()
        #iterate through all of the role config groups and stop each
        for group in role_config_groups.items:
            MngmtServices().build_api_role_list(group.name)
            body=cm_client.ApiRoleNameList(api_role_name_list)
            try:
                api_response = mngmt_api_instance.stop_command(body=body)
            except ApiException as e:
                logging.error('Exception running MgmtRoleCommandsResourceApi->stop_command {}\n'.format(e))
                
    def start(self):
        global api_role_name_list
        #Read all of the existing installed management role config groups
        role_config_groups = mngmt_rl_cfg_grp_api_instance.read_role_config_groups()
        #iterate through all of the role config groups and start each
        for group in role_config_groups.items:
            MngmtServices().build_api_role_list(group.name)
            body=cm_client.ApiRoleNameList(api_role_name_list)
            try:
                api_response = mngmt_api_instance.start_command(body=body)
            except ApiException as e:
                logging.error('Exception running MgmtRoleCommandsResourceApi->stop_command {}\n'.format(e))


def main():
    global cmd_api_instance
    global cm_api_instance
    global cluster_api_instance
    global mngmt_api_instance
    global mngmt_rl_cfg_grp_api_instance
    global service_api_instance
    global roles_api_instance
    global role_config_instance
    global host_api_instance
    
    conf_setup = ApiConfigurationSetup(cm_user, cm_pass, tls, ca_cert_path)
    cluster=Cluster()
    mgmnt=MngmtServices()
    kerberos=Kerberos() #Get instance of Kerberos Utility
    
    #Set up the API client and validate the kerberos ingestion script
    api_client = conf_setup.setup_api()
    conf_setup.validate_krb_ingest_script()
    
    #configure all API's to be used
    cmd_api_instance = cm_client.CommandsResourceApi(api_client)
    cm_api_instance = cm_client.ClouderaManagerResourceApi(api_client)
    cluster_api_instance = cm_client.ClustersResourceApi(api_client)
    mngmt_api_instance = cm_client.MgmtRoleCommandsResourceApi(api_client)
    mngmt_rl_cfg_grp_api_instance = cm_client.MgmtRoleConfigGroupsResourceApi(api_client)
    service_api_instance = cm_client.ServicesResourceApi(api_client)
    roles_api_instance = cm_client.RolesResourceApi(api_client)
    role_config_instance = cm_client.RoleConfigGroupsResourceApi(api_client)
    host_api_instance = cm_client.HostsResourceApi(api_client)
    
    kerberos.setup_cm_kerberos() #Set up Cloudera Manager
    kerberos.generate_credentials()
    
    cluster.stop() # Stop the cluster
    mgmnt.stop() #Stop all management services
    
    time.sleep(20)
    
    kerberos.apply_kerberos_service_configs()
    
    cluster.deploy_cluster_config()
    
    mgmnt.start() #Start all management services
    cluster.start()

if __name__ == '__main__':
    main()