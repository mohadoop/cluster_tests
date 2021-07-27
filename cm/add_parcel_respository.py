"""
  File Name: add_parcel_repository.py
  Author: Thomas Kreutzer
  Date created: July 27, 2021
  Date last modified: July 27, 2021
  Python Version: 2.7.5
  Description: Adds a parcel repository to cloudera manager if it is not existing
  
  Change Log:
  
  Change Number | Date MM-DD-YYYY  | Changed By        | Change Description
  Initial       | 07-20-2021       | Thomas Kreutzer   | Initial code draft 
  

"""

import json
import cm_client, random
from cm_client.rest import ApiException
from pprint import pprint
import logging
from logging import error
import socket

logger = logging.getLogger('parcel_repository')
logger.setLevel(logging.DEBUG)

cm_user = 'admin'
cm_pass = 'admin'
cm_api_version = 'v41'
cluster_name = 'CDP_cluster_0701_3'
tls=False
ca_cert_path = '/opt/cloudera/security/pki/rootCA.pem'

new_repo='https://username:pass@archive.cloudera.com/p/cfm2/2.2.1.0/redhat7/yum/tars/parcel/'

# Another service that must be installed
# https://username:password@archive.cloudera.com/p/keytrusteeserver7/7.1.1.0/parcels/


def setup_api():
    """
    Helper to set up the Cloudera Manager API
    This assumes that you are executing this script on the 
    Cloudera Manager host
    :return: api_client
    """
    global cm_api_version
    cm_host = socket.gethostname()
    cm_client.configuration.username = cm_user
    cm_client.configuration.password = cm_pass
    if tls:
        logging.info('Setting up with TLS true')
        cm_client.configuration.verify_ssl = tls
        cm_client.configuration.ssl_ca_cert = ca_cert_path
        api_host = 'https://{host}'.format(host=cm_host) + ':7183'
        api_url = api_host + '/api/' + cm_api_version
    else:
        logging.info("TLS is not enabled")
        api_host = 'http://{host}'.format(host=cm_host) + ':7180'
        api_url = api_host + '/api/' + cm_api_version
        
    api_client = cm_client.ApiClient(api_url)
    return api_client

def get_current_repos():
    try:
        api_response = cm_resource_api_instance.get_config(view='summary')
        repositories=''
        for item in api_response.items:
            if item.name == "REMOTE_PARCEL_REPO_URLS":
                repositories = item.value
        return repositories
    except ApiException as e:
        logger.error("Exception when calling ClouderaManagerResourceApi->get_config: %s\n" % e)

def add_new_repo(current_repos, new_repo):
    if new_repo not in current_repos:
        final_repo=current_repos + "," + new_repo
        update_repo(final_repo)
    else:
        logger.info("The repository already exists in the target cluster, no action has been taken!")

def update_repo(final_repo):
    message = 'Updating Repo with new config'
    body = cm_client.ApiConfigList([cm_client.ApiConfig(name='REMOTE_PARCEL_REPO_URLS', value=final_repo)])
    try:
        api_response = cm_resource_api_instance.update_config(message=message, body=body)
    except ApiException as e:
        logger.error("Exception when calling ClouderaManagerResourceApi->update_config: %s\n" % e)

if __name__ == '__main__':
    api_client = setup_api()
    
    #Set up API instances
    cm_resource_api_instance = cm_client.ClouderaManagerResourceApi(api_client)
    
    repositories = get_current_repos()
    add_new_repo(repositories, new_repo)
