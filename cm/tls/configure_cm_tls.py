
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
cm_api_instance = cm_client.ClouderaManagerResourceApi(api_client)

configs = []
configs.append(cm_client.ApiConfig(name='keystore_path', value='/opt/cloudera/security/pki/host_keystore.jks'))
configs.append(cm_client.ApiConfig(name='keystore_password', value='Cloudera123'))
configs.append(cm_client.ApiConfig(name='web_tls', value=True))
configs.append(cm_client.ApiConfig(name='agent_tls', value=True))

message = 'Updating Cloudera Manager with TLS configurations'
try: # Update the Cloudera Manager settings.
    api_response = cm_api_instance.update_config(message=message, body=cm_client.ApiConfigList(configs))
except ApiException as e:
    logging.error("Exception when calling ClouderaManagerResourceApi->update_config: %s\n" % e)
