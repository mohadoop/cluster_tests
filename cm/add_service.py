import cm_client, random
from cm_client.rest import ApiException
from pprint import pprint


cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'

# cm_client.configuration.verify_ssl = True
# cm_client.configuration.ssl_ca_cert = '/opt/cloudera/security/pki/rootCA.pem'

# Create an instance of the API class
api_host = 'http://ccycloud-1.tkreutzer.root.hwx.site'
port = '7180'
api_version = 'v41'
cluster_name = 'CDP_cluster_0701_3'

api_url = api_host + ':' + port + '/api/' + api_version
api_client = cm_client.ApiClient(api_url)
roles_api = cm_client.RolesResourceApi(api_client)
clusters_api = cm_client.ClustersResourceApi(api_client)
cluster_services_api = cm_client.ServicesResourceApi(api_client)
hosts_api = cm_client.HostsResourceApi(api_client)
role_config_group_api = cm_client.RoleConfigGroupsResourceApi(api_client)

'''
    Define the cluster, services, role types and role configuration groups 
    you are going to add for this script.
'''

service_dict = {
    'SOLR_SERVER': [{
        'service_name':'cdp-infra-solr',
        'service_type': 'SOLR',
        'display_name': 'CDP-INFRA-SOLR',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'RANGER_ADMIN': [{
        'service_name':'ranger',
        'service_type':'RANGER',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'RANGER_USERSYNC': [{
        'service_name':'ranger',
        'service_type':'RANGER',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'RANGER_TAGSYNC':[{
        'service_name':'ranger',
        'service_type':'RANGER',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'RANGER_KMS_SERVER':[{
        'service_name':'ranger_kms',
        'service_type':'RANGER_KMS',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'KNOX_GATEWAY': [{
        'service_name':'knox',
        'service_type':'KNOX',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'GATEWAY': [{
        'service_name':'knox',
        'service_type':'KNOX',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site','ccycloud-8.tkreutzer.root.hwx.site'}
    }],
    'KUDU_MASTER':[{
        'service_name':'kudu',
        'service_type':'KUDU',
        'hostname':{'ccycloud-4.tkreutzer.root.hwx.site'}
    }],
    'KUDU_TSERVER':[{
        'service_name':'kudu',
        'service_type':'KUDU',
        'hostname':{'ccycloud-6.tkreutzer.root.hwx.site','ccycloud-7.tkreutzer.root.hwx.site','ccycloud-8.tkreutzer.root.hwx.site'}
    }]
}



def add_host(hostname, host_id):
    """
    If a host was not found, it will attempt to add the host to the Cloudera Manager cluster provided.
    If this fails an exception will be thrown and the program will exit.
    :return: host_id
    """
    hosts = []
    hosts.append({'hostname': hostname, 'hostId': host_id})
    try:
        api_response = clusters_api.add_hosts(cluster_name, body=cm_client.ApiHostRefList(hosts))
    except ApiException as e:
        print("Exception when calling ClustersResourceApi->add_hosts: %s\n" % e)
        raise HostAddError


def read_hosts(hostname):
    """
    If this function is called, the host has not been added to the cluster
    This function will read all hosts in Cloudera Manager assigned or not.
    If the host is then not found, an error will be thrown because the host
    has not been prepared and added to CM.
    
    :return: host_id
    """
    return_host_id=""
    try:
        api_response = hosts_api.read_hosts()
        #pprint(api_response)
    except ApiException as e:
        print("Exception when calling HostsResourceApi->read_hosts: %s\n" % e)
    for host in api_response.items:
        if host.hostname == hostname:
            return_host_id = host.host_id
            break
    if return_host_id != "":
        #Add the host to the cluster
        add_host(hostname,return_host_id)
        return return_host_id
    else:
        raise HostUnavailableError
    
    
def get_host_id(hostname):
    """
    Takes a hostname and returns the Cloudera Manager host ID associated
    to the hostname.
    
    :return: host_id
    """
    return_host_id=""
    try:
        api_response = clusters_api.list_hosts(cluster_name)
        #pprint(api_response)
    except ApiException as e:
        print("Exception when calling ClustersResourceApi->list_hosts: %s\n" % e)
    for host in api_response.items:
        if host.hostname == hostname:
            return_host_id = host.host_id
            break
    if return_host_id != "":
        return return_host_id
    else:
        # Attempt to read all hosts in CM and add to cluster
        return read_hosts(hostname)


def define_cluster_service(cluster_name, service_name, service_type, display_name):
    """
    Sets up the cluster services
    :return:
    """
    api_service_list = []
    service_info = cm_client.ApiService(cluster_ref=cluster_name,
                                        display_name=display_name,
                                        name=service_name,
                                        type=service_type)
    api_service_list.append(service_info)
    body = cm_client.ApiServiceList(api_service_list)
    print('--->Defining Cluster Services')
    pprint(body)
    try:
        api_response = cluster_services_api.create_services(cluster_name, body=body)
    except ApiException as e:
        print('Exception when calling ServicesResourceApi->create_services: {}\n'.format(e))


def create_role_config_group(service_name, role_config_group_name, role_type, service_ref):
    """
    Creates the role config group
    :return:
    """
    try:
        acg = cm_client.ApiRoleConfigGroup(name=role_config_group_name, role_type=role_type, service_ref=service_ref)
        body = cm_client.ApiRoleConfigGroupList([acg])
        print('--->Creating Role Config Group for reference name %s, role type %s and service reference %s' % (role_config_group_name, role_type, service_ref))
        pprint(body)
        api_response = role_config_group_api.create_role_config_groups(cluster_name, service_name, body=body)
    except ApiException as e:
        print("Exception when calling RoleConfigGroupsResourceApi->create_role_config_groups: %s\n" % e)


def create_role(service_name, role_config_group_reference_name, role_type, host_ref, role_config_group_ref, service_ref):
    """
    Create Role to associate with cluster hosts, services and role config groups.
    :return:
    """
    role_api_packet = [cm_client.ApiRole(name=role_config_group_reference_name,
                                         type=role_type,
                                         host_ref=host_ref,
                                         role_config_group_ref=role_config_group_ref,
                                         service_ref=service_ref)]
    body = cm_client.ApiRoleList(role_api_packet)
    print('--->Creating Role %s for %s' % (role_config_group_reference_name, hostname))
    pprint(body)
    try:
        api_response = roles_api.create_roles(cluster_name, service_name, body=body)
    except ApiException as e:
        print('Exception when calling RolesResourceApi->create_roles: {}\n'.format(e))


if __name__ == '__main__':
    for key, values in service_dict.items():
        for value in values: 
            role_type = key
            service_type = value['service_type']
            service_name = value['service_name']
            hostnames = value['hostname']
            display_name = '' #Set default
            try: #is only set if a display name override is configured, as is the case for INFRA SOLR
                display_name = value['display_name']
            except:
                #if an override is not presented, create the display name as the service name lower case.
                display_name = service_name.lower()
                pass
            define_cluster_service(cluster_name, service_name, service_type, display_name)
            
            hostnames_arr=[]
            for hostname in hostnames:
                hostnames_arr.append(hostname)
            for i in range(len(hostnames)):
                hostname = hostnames_arr[i]
                host_id = get_host_id(hostname)
                
                role_config_group_name = service_type.lower() + '-' + role_type
                role_config_group_reference_name = role_config_group_name + '-' + str(i)
                host_ref = cm_client.ApiHostRef(host_id=host_id, hostname=hostname)
                role_config_group_ref = cm_client.ApiRoleConfigGroupRef(role_config_group_name)
                service_ref = cm_client.ApiServiceRef(cluster_name=cluster_name, service_name=service_name)
                #Create the role config group
                create_role_config_group(service_name, role_config_group_name, role_type, service_ref)
                #Create the role
                create_role(service_name, role_config_group_reference_name, role_type, host_ref, role_config_group_ref, service_ref)