from __future__ import print_function
import time
import cm_client
from cm_client.rest import ApiException
from pprint import pprint

# Configure HTTP basic authorization: basic
cm_client.configuration.username = 'admin'
cm_client.configuration.password = 'admin'


# Create an instance of the API class
api_host = 'http://ccycloud-1.tkreutzer.root.hwx.site'
port = '7180'
api_version = 'v41'


# Construct base URL for API
# http://cmhost:7180/api/v30
api_url = api_host + ':' + port + '/api/' + api_version
api_client = cm_client.ApiClient(api_url)

# create an instance of the API class
api_instance = cm_client.MgmtServiceResourceApi(api_client)


configs = []
configs.append(cm_client.ApiConfig(name='ssl_client_truststore_location', value='/usr/java/jdk1.8.0_232-cloudera/jre/lib/security/jssecacerts'))
configs.append(cm_client.ApiConfig(name='ssl_client_truststore_password', value='changeit'))

message = 'Updating Management Services for TLS'
body = cm_client.ApiServiceConfig(configs) # ApiServiceConfig | Configuration changes. (optional)

try:
    # Update the Cloudera Management Services configuration.
    api_response = api_instance.update_service_config(message=message, body=body)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling MgmtServiceResourceApi->update_service_config: %s\n" % e)