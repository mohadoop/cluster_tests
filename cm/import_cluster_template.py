# import_cluster_template.py

import cm_client
from cm_client.rest import ApiException
from collections import namedtuple
from pprint import pprint
import json


# Configure HTTP basic authorization for destination CM
cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'

api_url = "http://ccycloud-1.tkreutzer.root.hwx.site:7180/api/v41"
api_client = cm_client.ApiClient(api_url)
cm_api_instance = cm_client.ClouderaManagerResourceApi(api_client)

# Load the updated cluster template
with open('/root/cluster_template.json') as in_file:
    json_str = in_file.read()
    
print('Created JSON String')

# Following step is used to deserialize from json to python API model object
Response = namedtuple("Response", "data")
dst_cluster_template=api_client.deserialize(response=Response(json_str),
        response_type=cm_client.ApiClusterTemplate)
print('Destination cluster template created')

print('Attempting import')
command = cm_api_instance.import_cluster_template(body=dst_cluster_template)