import cm_client
from cm_client.rest import ApiException
from collections import namedtuple
from pprint import pprint
import json


# Configure HTTP basic authorization: basic
cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'
cm_client.configuration.verify_ssl = True

# Path of truststore file in PEM
cm_client.configuration.ssl_ca_cert = '/opt/cloudera/security/pki/rootCA.pem'



api_url = "https://ccycloud-1.tkreutzer.root.hwx.site:7183/api/v41"
api_client = cm_client.ApiClient(api_url)

# create an instance of the API class
cluster_name = 'CDP_cluster_0701_3'
clusters_api_instance = cm_client.ClustersResourceApi(api_client)
template = clusters_api_instance.export(cluster_name)
# Following step allows python fields with under_score to map
# to matching camelCase name in the API model before writing to json file.
json_dict = api_client.sanitize_for_serialization(template)
with open('/root/cluster_template.json', 'w') as out_file:
    json.dump(json_dict, out_file, indent=4, sort_keys=True)