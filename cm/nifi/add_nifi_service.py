
import cm_client
from cm_client.rest import ApiException
from pprint import pprint


cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'

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
service1 = 'NIFI'
service2 = 'NIFIREGISTRY'
rcg1 = "NIFI_NODE-BASE"
rcg2 = "NIFI_REGISTRY_SERVER-BASE"
role_type1="NIFI_NODE"
role_type2="NIFI_REGISTRY_SERVER"
cluster_service_list = [service1, service2]

'''
    Define the host names where each of the NiFi services are going to be installed.
'''
hosts1 = ["ccycloud-5.tkreutzer.root.hwx.site","ccycloud-6.tkreutzer.root.hwx.site"]
hosts2 = ["ccycloud-5.tkreutzer.root.hwx.site"]


class HostUnavailableError(Exception):
    """The host ID was not found when searching all of Cloudera Manager!"""
class HostAddError(Exception):
    """The host ID was found and an attempt made to add it to the cluster has failed!"""

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


def define_cluster_services(cluster_name, cluster_service_list):
    """
    Sets up the cluster services
    :return:
    """
    api_service_list = []
    for service in cluster_service_list:
        pprint("Adding service: " + service)
        service_info = cm_client.ApiService(cluster_ref=cluster_name, display_name=service.lower(), name=service.lower(),
                                            type=service)
        api_service_list.append(service_info)
    body = cm_client.ApiServiceList(api_service_list)
    try:
        api_response = cluster_services_api.create_services(cluster_name, body=body)
        pprint(api_response)
    except ApiException as e:
        print('Exception when calling ServicesResourceApi->create_services: {}\n'.format(e))


def create_role_config_group(service, ref_name, role_type, service_ref):
    try:
        # Creates new role config groups.
        acg = cm_client.ApiRoleConfigGroup(name=ref_name, role_type=role_type, service_ref=service_ref)
        acgl = cm_client.ApiRoleConfigGroupList([acg])
        print(acgl)
        api_response = role_config_group_api.create_role_config_groups(cluster_name, service.lower(), body=acgl)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling RoleConfigGroupsResourceApi->create_role_config_groups: %s\n" % e)
    


def create_role(rcg, role_type, service, host_id, hostname, instance_number):
    """
    Create Role to associate with cluster hosts, services and role config groups.
    :return:
    """
    ref_name = service.lower() + '-' + role_type
    instance_name = ref_name + '-' + str(instance_number)
    host_ref = cm_client.ApiHostRef(host_id=host_id, hostname=hostname)
    role_config_group_ref = cm_client.ApiRoleConfigGroupRef(ref_name)
    service_ref = cm_client.ApiServiceRef(cluster_name=cluster_name, service_name=service.lower())
    
    #Create the Role Config Group if it does not exist
    create_role_config_group(service, ref_name, role_type, service_ref)
    
    
    role_api_packet = [cm_client.ApiRole(name=instance_name, type=role_type, host_ref=host_ref,
                                         role_config_group_ref=role_config_group_ref, service_ref=service_ref)]
    body = cm_client.ApiRoleList(role_api_packet)
    print('--->Creating Role %s for %s' % (ref_name, hostname))
    pprint(body)
    try:
        api_response = roles_api.create_roles(cluster_name, service.lower(), body=body)
        pprint(api_response)
    except ApiException as e:
        print('Exception when calling RolesResourceApi->create_roles: {}\n'.format(e))
    

if __name__ == '__main__':
    define_cluster_services(cluster_name, cluster_service_list)

    #Add NiFi
    for i in range(len(hosts1)):
        hostname = hosts1[i]
        host_id = get_host_id(hostname)
        create_role(rcg1, role_type1, service1, host_id, hostname, i)
    #Add NiFi Registry
    for i in range(len(hosts2)):
        hostname = hosts2[i]
        host_id = get_host_id(hostname)
        create_role(rcg2, role_type2, service2, host_id, hostname, i)

