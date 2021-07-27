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
# create an instance of the API class
api_instance = cm_client.ClustersResourceApi(api_client)

try:
    # Updates all refreshable configuration files for services with Dynamic Resource Pools.
    api_response = api_instance.pools_refresh(cluster_name)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling ClustersResourceApi->pools_refresh: %s\n" % e)