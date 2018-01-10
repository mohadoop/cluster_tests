#!/bin/bash

# number of records to be generated for hive table
rand_count=${1:-1000}

# update the Zookeeper host list if you have enabled HA for HIVE
zk_hosts="<zk host1>:2181,<zk host2>:2181,<zk host3>:2181"
connect_string=$zk_hosts"/;serviceDiscoveryMode=zooKeeper;zooKeeperNamespace=hiveserver2"
 
# delete if the test table exists 
beeline -u $connect_string -e "drop table test.rand_test_table;"

# create Hive database 
beeline -u $connect_string -e "CREATE DATABASE test;"

# create Hive table
beeline -u $connect_string -e "CREATE TABLE test.rand_test_table (col1 STRING,col2 STRING,col3 INT ) Row format delimited Fields terminated by ',' stored as textfile;"
 
 
# create a CSV file with random values
hexdump -v -e '5/1 "%02x""\n"' /dev/urandom |
awk -v OFS=',' '
{ print substr($0, 1, 8), substr($0, 9, 2), int(NR * 32768 * rand()) }' |
head -n "$rand_count" > /tmp/random_values.csv
# Credits: https://github.com/SistemaStrategy/HiveDataPopulator
 
 
# put the random file in HDFS
hadoop fs -put /tmp/random_values.csv  /tmp/random_values.csv
 
# load data into hive test table
beeline -u $connect_string -e "LOAD DATA INPATH '/tmp/random_values.csv' OVERWRITE INTO TABLE test.rand_test_table;"
 
 
# select query test table
beeline -u $connect_string -e "SELECT * FROM test.rand_test_table limit 50;"
 
 
# run a mapReduce job on test table
beeline -u $connect_string -e "SELECT count(col3) FROM test.rand_test_table;"