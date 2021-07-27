import json

import cm_client
from cm_client.rest import ApiException
from collections import namedtuple
from pprint import pprint


# GLOBAL VARIABLES
json_input_file='service_properties_yarn_001.json'

cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'
cluster_name='CDP_cluster_0701_3'
api_url = "http://ccycloud-1.tkreutzer.root.hwx.site:7180/api/v41"
api_client = cm_client.ApiClient(api_url)
cm_api_instance = cm_client.ClouderaManagerResourceApi(api_client)
services_instance = cm_client.ServicesResourceApi(api_client)
role_config_instance = cm_client.RoleConfigGroupsResourceApi(api_client)

def read_json_file():
    with open(json_input_file) as in_file:
        json_str = in_file.read()
    return json_str

def handle_service_configs(service_configs, service_ref_name):
    configs = []
    for properties in service_configs:
        if properties.has_key('value'):
            configs.append(cm_client.ApiConfig(name=properties['name'], value=properties['value']))
#        elif properties.has_key('ref'):
#            configs.append(cm_client.ApiConfig(name=properties['name'], ref=properties['ref']))
    if len(configs) > 0:
        msg = 'Updating parameter(s) for {service_type}'.format(service_type=service_ref_name)
        try:
            api_response = services_instance.update_service_config(cluster_name=cluster_name, service_name=service_ref_name, message=msg,body=cm_client.ApiConfigList(configs))
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
                configs.append(cm_client.ApiConfig(name=properties['name'], value=properties['value']))
            try:
                print(msg)
                api_response = role_config_instance.update_config(cluster_name=cluster_name, 
                                                                  role_config_group_name=rcg['refName'],
                                                                  service_name=service_ref_name,
                                                                  message=msg, 
                                                                  body=cm_client.ApiConfigList(configs))
                print('Response!')
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

if __name__ == '__main__':
    iterate_json(read_json_file())