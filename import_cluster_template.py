import time
import cm_client
from cm_client.rest import ApiException
from collections import namedtuple
from pprint import pprint
import json

# Configure HTTP basic authorization for destination CM

cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'

CM_HOST = 'http://host'
PORT = '7180'
API_VERSION = 'v43'
CLUSTER_NAME = 'CDPTest'                                                        
api_url = CM_HOST + ':' + PORT + '/api/' + API_VERSION

api_client = cm_client.ApiClient(api_url)
cm_api_instance = cm_client.ClouderaManagerResourceApi(api_client)

#add_repositories = false

# Load the updated cluster template
with open('Services_template.json') as in_file:
    json_str = in_file.read()
print('Created JSON String')

# Following step is used to deserialize from json to python API model object
Response = namedtuple("Response", "data")
dst_cluster_template=api_client.deserialize(response=Response(json_str),
        response_type=cm_client.ApiClusterTemplate)
print('Destination cluster template created')
print('Attempting import')
command = cm_api_instance.import_cluster_template(body=dst_cluster_template)