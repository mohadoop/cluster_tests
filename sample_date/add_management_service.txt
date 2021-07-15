# add_management_service.py
import time
import cm_client
from cm_client.rest import ApiException
from collections import namedtuple
from pprint import pprint
import json
# Configure HTTP basic authorization: basic
cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'

#Create an instance of the API class
CM_HOST = 'ccycloud-1.tkreutzerautomation.root.hwx.site'
PORT = '7180'
API_VERSION = 'v43'
CLUSTER_NAME = 'Cluster1'
api_url = CM_HOST + ':' + PORT + '/api/' + API_VERSION

print("Calling URL " + api_url)
api_client = cm_client.ApiClient(api_url)
cm_mgmt_instance = cm_client.MgmtServiceResourceApi(api_client)

# Load the updated cluster template
with open('management_service.json') as in_file:
    json_str = in_file.read()
print('Created JSON String')

# Following step is used to deserialize from JSON to Python API model object
Response = namedtuple("Response", "data")
dst_cluster_template=api_client.deserialize(response=Response(json_str),
        response_type=cm_client.ApiClusterTemplate)


print('Destination cluster template created')
print('Attempting to Add Cloudera Management Services')

command = cm_mgmt_instance.setup_cms(body=dst_cluster_template)

pprint(command)