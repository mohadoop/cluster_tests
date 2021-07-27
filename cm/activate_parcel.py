"""
  File Name: activate_parcel_repository.py
  Author: Thomas Kreutzer
  Date created: July 27, 2021
  Date last modified: July 27, 2021
  Python Version: 2.7.5
  Description: Once a parcel has been added to CM, this will call to download, distribute and activate the parcel.
  
  Change Log:
  
  Change Number | Date MM-DD-YYYY  | Changed By        | Change Description
  Initial       | 07-20-2021       | Thomas Kreutzer   | Initial code draft 
"""
import time
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

product='KEYTRUSTEE_SERVER'
version='7.1.6'
parcel_check_wait_time=5

"""
  Other possible products
  CFM
"""
class ParcelNotFoundError(Exception):
    """The parcel you are requesting has not been configured in Cloudera Manager."""
    
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


def extract_parcel_by_version(parcels):
    parcel=''
    for item in parcels.items:
        if product == item.product and version in item.version:
            parcel = item
    if parcel == '':
        raise ParcelNotFoundError
    else:
        return parcel

def get_parcel_info():
    try:
        parcels = parcels_api_instance.read_parcels(cluster_name)
        return extract_parcel_by_version(parcels)
    except ApiException as e:
        print("Exception when calling ParcelsResourceApi->read_parcels: %s\n" % e)
        
        
def start_parcel_download(parcel_info):
    try:
        parcel_api_instance.start_download_command(cluster_name, parcel_info.product, parcel_info.version)
        wait_for_status('DOWNLOADED')
    except ApiException as e:
        print("Exception when calling ParcelResourceApi->start_download_command: %s\n" % e)
        
def start_parcel_distribution(parcel_info):
    try:
        parcel_api_instance.start_distribution_command(cluster_name, parcel_info.product, parcel_info.version)
        wait_for_status('DISTRIBUTED')
    except ApiException as e:
        print("Exception when calling ParcelResourceApi->start_distribution_command: %s\n" % e)
        
def start_parcel_activation(parcel_info):
    try:
        parcel_api_instance.activate_command(cluster_name, parcel_info.product, parcel_info.version)
        wait_for_status('ACTIVATED')
    except ApiException as e:
        print("Exception when calling ParcelResourceApi->activate_command: %s\n" % e)
    
def wait_for_status(expected_stage):
    waiting=True
    while waiting:
        time.sleep(parcel_check_wait_time)
        parcel_info = get_parcel_info()
        log.debug("Parcel is currently in the stage {c}, waiting for the expected stage {w}".format(c=parcel_info.stage,w=expected_stage))
        if parcel_info.stage == expected_stage:
            waiting=False

if __name__ == '__main__':
    api_client = setup_api()
    
    parcels_api_instance = cm_client.ParcelsResourceApi(api_client)
    parcel_api_instance = cm_client.ParcelResourceApi(api_client)
    
    parcel_info = get_parcel_info()
    if parcel_info.stage == 'AVAILABLE_REMOTELY':
        start_parcel_download(parcel_info)
    
    #Pull the parcel information again
    parcel_info = get_parcel_info()
    if parcel_info.stage == 'DOWNLOADED':
        start_parcel_distribution(parcel_info)
    
    #Pull the parcel information again
    parcel_info = get_parcel_info()
    if parcel_info.stage == 'DISTRIBUTED':
        start_parcel_activation(parcel_info)
        
    #Pull the parcel information again
    parcel_info = get_parcel_info()
    if parcel_info.stage == 'ACTIVATED':
        logger.info("The parcel {p} has been activated".format(p=parcel_info.product))