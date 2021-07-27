### Goal
Provide Citi with scripts to assist in automation.
All of these scripts are examples and will need to be updated or modified for your environment.


#### Example templates
Example templates have been provided to assist them with the first part of the install.


#### Apply Properties
This script leverages JSON in the same format as a template that gets exported by Cloudera Manager but only contains the services section.
It iterates through the JSON and looks for **serviceConfigs** or **roleConfigGroups** and then applies these properties to the associated Service/role config. If they role config group or service does not exist in the cluster you will likely encounter as the names are expected to match that of your installation.

The apply properties script **DOES NOT** make changes for Cloudera Manager configurations.

