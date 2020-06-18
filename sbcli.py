#!/usr/bin/python3

import ipaddress
import logging.config
import operator
import re
import urllib.parse

import configargparse
import requests
import requests_cache
import zeep

requests.packages.urllib3.disable_warnings()
from datetime import datetime
import arrow
import os
from bravado.requests_client import RequestsClient
from bravado.client import SwaggerClient
import time
import ssl
from elasticsearch import Elasticsearch
from elasticsearch.connection import create_ssl_context
import csv
import sys
from netaddr import *

SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from sbfunctions import *

def listMethods(client):
    methods = []
    for service in client.wsdl.services.values():
        for port in service.ports.values():
            operations = sorted(
                port.binding._operations.values(),
                key=operator.attrgetter('name'))

            for operation in operations:
                print("method :", operation.name)
                print("  input :", operation.input.signature())
                print()
                methods.insert(1,operation.name)
        print()

def esConnect():
    if not cfg.esurl:
        logging.error("You need to configure --esurl, --esuser, --espass, --escrt!")
        sys.exit(2)
    e = urllib.parse.urlparse(cfg.esurl)
    if cfg.escrt:
        scontext = create_ssl_context(cafile=cfg.escrt)
        scontext.check_hostname = False
        scontext.verify_mode = ssl.CERT_NONE
    else:
        scontext = create_ssl_context()
    es = Elasticsearch(
        [e.hostname],
        http_auth=(cfg.esuser, cfg.espass),
        scheme=e.scheme,
        port=e.port,
        ssl_context=scontext
    )
    return(es)

def findByQuery(index, query, size=1000, scroll="2m"):
    rr = es.search(index=index, body={}, q="_index:%s" % index + " " + query, scroll=scroll, size=size)
    return(rr)

def findNext(es, scroll_id, scroll="2m"):
    rr = es.scroll(scroll_id=scroll_id, scroll=scroll)
    return(rr)

def findRouteByIpRange(network):
    es = esConnect()
    logging.warning("Searching for network %s" % network)
    rr = es.search(index="model_routing_rules-" + cfg.date, body={
     "sort": { "_index" : {"order" : "desc"}},
     "size": "200",
      "query": {
        "bool": {
          "must": [
            {
              "term": {
                "destinationIPAddress": str(network.network_address)
              }
            },
            {
              "term": {
                "destinationNetMask": network.prefixlen
              }
            }
          ]
        }
      }
    })
    ret = []
    for rule in rr["hits"]["hits"]:
        ret.append(rule["_source"])
    return(ret)
    
def findNetworksInPerimeterCloud(netname):
    es = esConnect()
    logging.warning("Searching for perimeter cloud %s" % netname)
    rr = es.search(index="model_networks-" + cfg.date, body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": "1",
      "query": {
                "match_phrase" : { 
                    "name": {
                        "query": netname
                    }
                }
            }
      }
    )
    ips={}
    included = rr["hits"]["hits"][0]["_source"]
    for n in included["includedIPRangesCIDR"]:
        ipn = IpRangeToIps(n)
        for ip in ipn:
            ips[str(ip)]=ip
    logging.warning("findNetworksInPerimeterCloud: %s > %s" % (included["name"], ips))
    return(ips)

def findNetworksByName(netname, type=None):
    es = esConnect()
    logging.warning("Searching for network %s" % netname)
    rr = es.search(index="model_networks-" + cfg.date, body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
      "query": {
                "match_phrase" : { 
                    "name": {
                        "query": netname
                    }
                }
            }
      }
    )
    ips={}
    for result in rr["hits"]["hits"]:
        if type:
            if result["_source"]["networkTypeEnum"] != type:
                continue
        n = "%s/%s" % (result["_source"]["networkIPAddress"], result["_source"]["networkNetMask"])
        ip = ipaddress.ip_network(n)
        ips[str(ip)] = { "ip": ip, "id": result["_source"]["id"], "name": result["_source"]["name"], "type": result["_source"]["networkTypeEnum"] }
    logging.warning("findNetworksByName: %s > %s" % (netname, ips))
    return(ips)

def findFirewallsWithoutZones():
    es = esConnect()
    logging.warning("Searching for firewalls without zones")
    rr = es.search(index="model_net_interfaces-" + cfg.date, body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
        "size": 1000,
      "query": {
          "bool": {
              "must": {
                "match" : {
                    "hostTypeEnum": {
                        "query": "Firewall"
                    }
                }
              },
              "must_not": { "match" : {
                      "type": {
                          "query": "Loopback"
                      }
                  }
                }
          }
      }
      }
    )
    ips={}
    for result in rr["hits"]["hits"]:
        row = result["_source"]
        if not row["zoneType"]:
            ips[row["hostId"]] = row["hostName"]
    return(ips)

def findNetworksById(netid):
    es = esConnect()
    logging.warning("Searching for networkid %s" % netid)
    rr = es.search(index="model_networks-" + cfg.date, body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": "1",
      "query": {
                "match" : { 
                    "id": {
                        "query": netid
                    }
                }
            }
      }
    )
    result = rr["hits"]["hits"][0]
    n = "%s/%s" % (result["_source"]["networkIPAddress"], result["_source"]["networkNetMask"])
    ip = ipaddress.ip_network(n)
    loc = result["_source"]["hierLocationPath"].replace(";"," / ")
    return(
        { "ip": ip, "id": result["_source"]["id"], "name": result["_source"]["nameForDisplay"], "type": result["_source"]["networkTypeEnum"],
        "IPAddress": result["_source"]["networkIPAddress"], "netMask": result["_source"]["networkNetMask"], "location": loc
        }
        )

def IpRangeToIps(iprange):
    if ("-" in iprange):
        [first, last] = iprange.split("-")
        fip = ipaddress.IPv4Address(first)
        lip = ipaddress.IPv4Address(last)
        ips=None
        for i in range(0,30):
            tf = ipaddress.IPv4Network("%s/%s" % (first, i),strict=None)
            tl = ipaddress.IPv4Network("%s/%s" % (last, i),strict=None)
            firsthost = ipaddress.IPv4Address(int(next(tf.hosts()))-1)
            lasthost = ipaddress.IPv4Address(int(firsthost)+pow(2,32-i)-1)
            if tf==tl and tf.network_address==fip and lasthost==lip:
                return([tf])
                break
        if not ips:
            ips = cidr_merge(list(iter_iprange(first, last)))
    else:
        ips=[iprange]
    return(ips)

def findAclsByIpRange(fromip, toip, query):
    es = esConnect()
    if not fromip:
        fromip = ipaddress.IPv4Network("0.0.0.0/0")
    else:
        fromip = ipaddress.IPv4Network(fromip)
    if not toip:
        toip = ipaddress.IPv4Network("0.0.0.0/0")
    else:
        toip = ipaddress.IPv4Network(toip)
    logging.warning("Searching for ACLs for connections from %s to %s" % (fromip, toip))
    acls = es.search(index="model_access_rules-" + cfg.date, scroll="10m", body={
        "sort": {"_index": {"order": "desc"}, "_score": {"order": "desc"}},
        "size": 1000,
        "query": {
            "query_string": {
                "query": query
            }
        }
        }
    )
    scroll_size = len(acls['hits']['hits'])
    scroll_id = acls["_scroll_id"]
    processed=0
    skipped=0
    ignored=0
    rr = acls["hits"]["hits"]
    ret={}
    while scroll_size > 0:
        for row in rr:
            sips = row["_source"]["sourceAddresses"]
            dips = row["_source"]["destinationAddresses"]
            if not sips or not dips or len(sips)>cfg.maxaclobjects or len(dips)>cfg.maxaclobjects:
                logging.debug("Ignoring ACL with more or bad objects: %s" % (row["_source"]["id"]))
                ignored += 1
                continue
            if row["_source"]["sourceIsNegated"]:
                snegated = True
            else:
                snegated = False
            if not isinstance(sips, list):
                sips = [sips]
            if row["_source"]["destinationIsNegated"]:
                dnegated = True
            else:
                dnegated = False
            if not isinstance(dips, list):
                dips = [dips]
            for sip in sips:
                if sip=="Any":
                    sip = ipaddress.IPv4Network("0.0.0.0/0")
                    skipped +=1
                    continue
                for dip in dips:
                    if dip == "Any":
                        dip = ipaddress.IPv4Network("0.0.0.0/0")
                        skipped += 1
                        continue
                    sips2 = IpRangeToIps(sip)
                    dips2 = IpRangeToIps(dip)
                    for sip2 in sips2:
                        for dip2 in dips2:
#                            print(sip, sip2, dip, dip2)
                            if fromip.overlaps(ipaddress.IPv4Network(sip2))!=snegated and toip.overlaps(ipaddress.IPv4Network(dip2))!=dnegated:
                                ret[row["_source"]["id"]]= row["_source"]
            processed += 1
            if (processed % 100)==500:
                logging.warning("Processed %s acls, skipped %s (any), ignored %s" % (processed, skipped, ignored))

        acls = findNext(es, scroll_id)
        scroll_size = len(acls['hits']['hits'])
        rr = acls["hits"]["hits"]
    return (ret)

def findNetworksByLocation(location, type=None):
    es = esConnect()
    location = location.replace(" / ",";")
    logging.warning("Searching for networks in location %s" % location)
    rr = es.search(index="model_networks-" + cfg.date, body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 1000,
      "query": {
                "match_phrase" : { 
                    "hierLocationPath": {
                        "query": location
                    }
                }
            }
      }
    )
    ips={}
    for result in rr["hits"]["hits"]:
        if type:
            if result["_source"]["networkTypeEnum"] != type:
                continue
        n = "%s/%s" % (result["_source"]["networkIPAddress"], result["_source"]["networkNetMask"])
        ip = ipaddress.ip_network(n)
        loc = result["_source"]["hierLocationPath"].replace(";"," / ")
        ips[str(ip)] = { "location": loc, "ip": ip, "id": result["_source"]["id"], "name": result["_source"]["name"], "type": result["_source"]["networkTypeEnum"], "networkGUIName": result["_source"]["networkGUIName"] }
    return(
        ips
        )

def findAssetsByLocation(location):
    es = esConnect()
    location = location.replace(" / ","&")
    r = re.match("(Loc.*?);(.*?);(.*)",location)
    if r:
        location = r.group(2) + ";Locations;" + r.group(3)
        location2 = r.group(2) + ";Locations;" + r.group(3)
        location2 = location2.replace(" ",".*").replace("(","?").replace(")","?")
    logging.warning("Searching for assets in location %s (%s)" % (location, location2))
    body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 1000,
      "query": {
                "match" : { 
                    "hierBusinessPaths": {
                        "query": location
                    }
                }
            }
      }
    assets = es.search(index="model_hosts-" + cfg.date, scroll="2m", body=body)
    scroll_size = len(assets['hits']['hits'])
    scroll_id = assets["_scroll_id"]
    rr = assets["hits"]["hits"]
    filtered=[]
    for row in rr:
        for p in row["_source"]["hierBusinessPaths"]:
            if re.match(location2, p):
                filtered.append(row)
    while scroll_size > 0:
        assets = findNext(es, scroll_id)
        for row in rr:
            for p in row["_source"]["hierBusinessPaths"]:
                if re.match(location2, p):
                    filtered.append(row)
        scroll_size = len(assets['hits']['hits'])
    return(filtered)

def findAllAssets(query=None):
    es = esConnect()
    logging.warning("Searching for all assets (query=%s)" % query)
    if not query:
        body={
         "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
         "size": 1000,
          "query": {
                    "match_all" : { 
                        }
                    }
                }
    else:
        body={
         "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
         "size": 1000,
          "query": {
                    "query_string" : { 
                        "query" : query
                        }
                    }
                }
    assets = es.search(index="model_hosts-" + cfg.date, scroll="2m", body=body)
    rr = assets["hits"]["hits"]
    scroll_size = len(rr)
    scroll_id = assets["_scroll_id"]
    while scroll_size > 0:
        logging.debug("Fetched %s assets..." % (scroll_size))
        assets = findNext(es, scroll_id)
        scroll_id = assets["_scroll_id"]
        scroll_size = len(assets["hits"]["hits"])
        if scroll_size>0:
            rr.extend(assets["hits"]["hits"])
    return(rr)
        
def getLocation(id):
    es = esConnect()
    logging.warning("Searching for locationid %s" % (id))
    rr = es.search(index="model_hierarchy_groups-*", body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 1000,
      "query": {
                "match" : { 
                    "id": {
                        "query": id
                    }
                }
            }
      }
    )
    locs={}
    result = rr["hits"]["hits"][0]
    path = result["_source"]["paths"][0]
    name = result["_source"]["name"]
    return(path)

def findMissingNeighbors():
    es = esConnect()
    logging.warning("Searching for missing neigbors")
    rr = es.search(index="model_net_interfaces-" + cfg.date, scroll="2m", body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 100,
      "query": {
                "exists" : { 
                    "field": "missingNeighbors"
                }
            }
      }
    )
    ips={}
    index=None
    scroll_size = len(rr["hits"]["hits"])
    scroll_id = rr["_scroll_id"]
    while scroll_size > 0:
        logging.debug("Fetched %s misshops..." % (scroll_size))
        for result in rr["hits"]["hits"]:
            if index==None:
                index = result["_index"]
            else:
                if index!=result["_index"]:
                    return(ips)
            ip = result["_source"]["missingNeighbors"]
            for i in ip:
                i = i.strip()
                if i not in ips:
                    if "connectivityIssue" in result["_source"]:
                        issue = result["_source"]["connectivityIssue"]
                    else:
                        issue=None
                    ipmask = ipaddress.ip_network(result["_source"]["ipAddress"] + "/" + result["_source"]["subnetMask"], False)
                    ips[i] = { "ip": i, "ipRangesOfAddrsBehindCount": [str(result["_source"]["ipRangesOfAddrsBehindCount"])],
                                "hostIp": [result["_source"]["hostIp"]], "ipmask": ipmask, "hostName": [result["_source"]["hostName"]], "networkGUIName": result["_source"]["networkGUIName"],
                                "viewed": result["_source"]["viewed"], "exportDate": result["_index"], "connectivityIssue": issue, "type": [result["_source"]["type"]]
                            }
                else:
                    ips[i]["ipRangesOfAddrsBehindCount"].append(str(result["_source"]["ipRangesOfAddrsBehindCount"]))
                    ips[i]["hostName"].append(result["_source"]["hostName"])
                    ips[i]["type"].append(str(result["_source"]["type"]))
                    if result["_source"]["viewed"] != ips[i]["viewed"]:
                        ips[i]["viewed"] = "mixed"

        rr = findNext(es, scroll_id)
        scroll_id = rr["_scroll_id"]
        scroll_size = len(rr["hits"]["hits"])
    return(ips)

def findNetworkIssues():
    es = esConnect()
    logging.warning("Searching for network issues")
    rr = es.search(index="model_net_interfaces-" + cfg.date, scroll="2m", body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 100,
      "query": {
                "exists" : { 
                    "field": "connectivityIssue"
                }
            }
      }
    )
    issues={}
    scroll_size = len(rr["hits"]["hits"])
    scroll_id = rr["_scroll_id"]
    while scroll_size > 0:
        logging.debug("Fetched %s issues..." % (scroll_size))
        for result in rr["hits"]["hits"]:
            nid = result["_source"]["id"]
            ipmask = ipaddress.ip_network(result["_source"]["ipAddress"] + "/" + result["_source"]["subnetMask"], False)
            issues[nid] = { "id": nid, "ipRangesOfAddrsBehindCount": result["_source"]["ipRangesOfAddrsBehindCount"],
                                "hostIp": result["_source"]["hostIp"], "hostName": result["_source"]["hostName"], "ipmask": ipmask, "networkGUIName": result["_source"]["networkGUIName"], 
                                "viewed": result["_source"]["viewed"], "exportDate": result["_index"], "connectivityIssue": result["_source"]["connectivityIssue"], "type": result["_source"]["type"]
                            }
        rr = findNext(es, scroll_id)
        scroll_id = rr["_scroll_id"]
        scroll_size = len(rr["hits"]["hits"])
    return(issues)

def findNetworksByLocationId(locationid, type=None):
    es = esConnect()
    logging.warning("Searching for networks in locationid %s" % locationid)
    location = getLocation(locationid)
    if location:
        rr = es.search(index="model_networks-" + cfg.date, body={
         "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
         "size": 1000,
          "query": {
                    "match_phrase" : { 
                        "hierLocationPath": {
                            "query": location
                        }
                    }
                }
          }
        )
        ips={}
        for result in rr["hits"]["hits"]:
            if type:
                if result["_source"]["networkTypeEnum"] != type:
                    continue
            n = "%s/%s" % (result["_source"]["networkIPAddress"], result["_source"]["networkNetMask"])
            ip = ipaddress.ip_network(n)
            loc = result["_source"]["hierLocationPath"].replace(";"," / ")
            ips[str(ip)] = { "location": loc, "ip": ip, "id": result["_source"]["id"], "name": result["_source"]["name"], "type": result["_source"]["networkTypeEnum"] }
        return(
            ips
            )
    else:
        return(None)
        
def findLocations():
    es = esConnect()
    logging.warning("Searching for locations")
    rr = es.search(index="model_hierarchy_groups-*", body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 1000,
      "query": {
                "match" : { 
                    "typeEnum": {
                        "query": "Location"
                    }
                }
            }
      }
    )
    locs={}
    for result in rr["hits"]["hits"]:
        id_ = result["_source"]["id"]
        path = result["_source"]["paths"][0].replace(";"," / ")
        name = result["_source"]["name"]
        locs[str(id_)] = { "location": path, "name": name, "id": id_ }
    return(
        locs
        )

def findRuleByObject(object):
    es = esConnect()
    rr = es.search(index="csv_access_rules_review_all_firewalls-*", body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 100,
      "query": {
    "bool": {
      "should": [
        {
          "match_phrase": {
            "Destination": {
              "query": object
            }
          }
        },
        {
          "match_phrase": {
            "Source": {
              "query": object
            }
          }
        }
      ],
        "must": [
            {
            "range": {
                "exportDate": {
                    "gte": "now-1d/d",
                    "lt": "now/d"
        }
    }
            }
        ],
      "filter": [],
      "must_not": []
    }
  } }
    )
    acls={}
    for result in rr["hits"]["hits"]:
        id_ = result["_source"]["EID"]
        #locs[str(id_)] = { "location": path, "name": name, "id": id_ }
        acls[str(id_)] = { "RuleNumber": result["_source"]["RuleNumber"],
                           "RuleCompliance": result["_source"]["RuleCompliance"],
                           "RuleComplianceMaxSeverity": result["_source"]["RuleComplianceMaxSeverity"],
                           "FAAccessCompliance": result["_source"]["FAAccessCompliance"],
                           "FAAccessMaxSeverity": result["_source"]["FAAccessMaxSeverity"],
                           "FAAccessChecks": result["_source"]["FAAccessChecks"],
                           "RuleChecks": result["_source"]["RuleChecks"],
                           }
    return(
        acls
        )

def getRuleById(hostid, aclid):
    es = esConnect()
    rr = es.search(index="csv_access_rules_review_all_firewalls-*", body={
     "sort": { "_index" : {"order" : "desc"}, "_score" : {"order" : "desc"}},
     "size": 100,
      "query": {
    "bool": {
      "must": [
        {
          "match": {
            "RuleNumber": {
              "query": aclid
            }
          }
        },
          {
              "match": {
                  "HostID": {
                      "query": hostid
                  }
              }
          },
          {
              "range": {
                  "exportDate": {
                      "gte": "now-1d/d",
                      "lt": "now/d"
                  }
              }
          }
      ],
        "should": [
        ],
      "filter": [],
      "must_not": []
    }
  } }
    )
    acls={}
    for result in rr["hits"]["hits"]:
        id_ = result["_source"]["EID"]
        #locs[str(id_)] = { "location": path, "name": name, "id": id_ }
        acls[str(id_)] = { "RuleNumber": result["_source"]["RuleNumber"],
                           "RuleCompliance": result["_source"]["RuleCompliance"],
                           "RuleComplianceMaxSeverity": result["_source"]["RuleComplianceMaxSeverity"],
                           "FAAccessCompliance": result["_source"]["FAAccessCompliance"],
                           "FAAccessMaxSeverity": result["_source"]["FAAccessMaxSeverity"],
                           "FAAccessChecks": result["_source"]["FAAccessChecks"],
                           "RuleChecks": result["_source"]["RuleChecks"],
                           }
    return(
        acls
        )

def getTypeId(nettype):
    types = {
        "Regular": 0,
        "Cloud": 1,
        "Perimeter Cloud": 1,
        "Tunel": 2,
        "Link": 3,
        "VPN Tunnel": 4,
        "SerialLink": 5,
        "Connecting Cloud": 6,
        "Artificial Layer2": 7
    }
    return(types[nettype])

def setDebug():
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })
    
def helpMsg(p):
    print(p.format_help())
    print(p.format_values())
    sys.exit()

def findAssetsByNames(client, hosts):
    results = {}
    for h in hosts:
        result = client.service['findAssetsByNames'](names=h)
        if result.status.code != 0:
            print("Bad status code! Exiting")
            print(result.status)
            sys.exit(2)
        else:
            if len(result.assets)>0:
                for i in result.assets:
                    if cfg.type:
                        if cfg.type == i.type:
                            results[i.id] = i
                    else:
                        results[i.id] = i
    return(results)

def findAssetsByIps(client, ips):
    results = {}
    for i in ips:
        result = client.service['findAssetsByIps'](ipRanges=i)
        if result.status.code != 0:
            print("Bad status code! Exiting")
            print(result.status)
            sys.exit(2)
        else:
            if len(result.assets)>0:
                for i in result.assets:
                    if cfg.type:
                        if cfg.type == i.type:
                            results[i.id] = i
                    else:
                        results[i.id] = i
    return(results)

def getChangeRequestsPerTicket(ticketid):
    IMP={
        "VERYLOW": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
        "NO_SEVERITY": -1
    }
    IMPR=dict((v,k) for k,v in IMP.items())
    SEV={
        "Info": 0,
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    SEVR=dict((v,k) for k,v in SEV.items())
    changes = client_tickets.service['getOriginalChangeRequestV7'](ticketId=ticketid)
    for t in changes:
        violations = client_tickets.service['getPolicyViolations'](ticketId=ticketid, changeRequestId=t['id'])
        vulnerabilities = client_tickets.service['getPotentialVulnerabilities'](ticketId=ticketid, changeRequestId=t['id'])
        severity = 0
        for v in vulnerabilities:
            severity=max(severity, SEV[v["severityLevel"]])
        importance = 0
        for v in violations:
            importance=max(importance, IMP[v["importance"]])
    for t in changes:
        t['severity'] = SEVR[severity]
        t['importance'] = IMPR[importance]
    return(changes)
    
def getAccessChangeTicket(id):
    ticket = client_tickets.service['getAccessChangeTicket'](ticketId=id)
    return(ticket)
    
def detectIPNet(ip):
    if re.search("(.*):(.*)/(.*)",ip):
        return(3)
    elif re.search("/",ip):
        return(2)
    elif re.search(":$",ip):
        return(4)
    else:
        return(1)

def ipsToEl(ips, forceid):
    el=[]
    if ips:
        for ip in ips:
            netid = forceid
            if detectIPNet(ip)==2:
                ip2 = ipaddress.ip_network(ip)
            elif detectIPNet(ip)==4:
                r = re.search("(.*):",ip)
                netid = r.group(1)
                ip2 = ipaddress.ip_network("0.0.0.0/0")
            elif detectIPNet(ip)==1:
                ip2 = ipaddress.ip_network(ip + "/32")
            else:
                r = re.search("(.*):(.*)",ip)
                ip2 = ipaddress.ip_network(r.group(2))
                if re.search("^[0123456789]*$", r.group(1)):
                    netid = r.group(1)
                else:
                    nets = findNetworksByName(r.group(1))
                    for i in nets:
                        netid = nets[i]["id"]
            if not netid:
                cip = client.service['findNetworks'](ipRange=ip2)
                if cip.status.code != 0:
                    print("Bad status code! Exiting")
                    print(cip.status)
                    sys.exit(2)
                ip3 = ipaddress.ip_network(cip.netElements[0]['IPAddress'] + "/" + str(cip.netElements[0]['netMask']))
                if len(cip.netElements)<1 and not ip3.overlaps(ip2):
                    print("IP %s does not exists in model? (found=%s)" % (ip, ip2))
                    sys.exit(3)
                else:
                    cip.netElements[0]["ip"] = str(ip2)
                    el.append(cip.netElements[0])
            else:
                net = findNetworksById(netid)
                el.append({ "ip": str(ip2), "IPAddress": net["IPAddress"], "type": getTypeId(net["type"]), "id": net["id"], "netMask": net['netMask'], "name": net['name'], "path": net["location"] })
    else:
        print("Source IP or ID is needed! Like [Netid:]IP/mask")
        sys.exit(2)
    return(el)

def aQuery(srcel, dstel, cfg):
    srcips = []
    for n in srcel:
        srcips.append(n["ip"])
        del n["ip"]
    dstips = []
    for n in dstel:
        dstips.append(n["ip"])
        del n["ip"]
    
    modes={
        "Accessible": 0,
        "Inaccessible": 1,
        "Both": 2
    }
    query={
        "mode": modes[cfg.amode],
        "useAccessRules": 1,
        "useRoutingRules": 1,
        "sourceAddresses": srcips,
        "destinationAddresses": dstips,
        "sourceElements": srcel,
        "destinationElements": dstel
    }
    if cfg.ports:
        query["ports"] = ",".join(cfg.ports)

        logging.debug(query)
    result = client.service['checkAccessV3'](routeOutputType=1, query=query)
    if result.status.code != 0:
        print("Bad status code! Exiting")
        print(result.status)
        sys.exit(2)
    return(result.route)

def postProcessAssets(assets):
    csv = initOutput('id', 'ip', 'name', 'corename', 'type', 'site', 'sitelong', 'routingRules', 'created', 'modified',  'created_by', 'modified_by', 'cmdbid')
    ids={}
    for a in assets:
        asset = a["_source"]
        id_ = asset["id"]
        if not id_ in ids:
            r = re.search("^(.*?)[\.\:]", asset["hostPrimaryName"])
            if r:
                corename = r.group(1)
            else:
                corename = asset["hostPrimaryName"]
            cmdbattr="C_" + cfg.cmdbidattr
            if cmdbattr in asset:
                cmdbid = asset[cmdbattr]
            else:
                cmdbid=""
            loc = ""
            loc2 = ""
            for p in asset["hierBusinessPaths"]:
                if re.search("Locations;", p):
                    r = re.search(";([^;]*)$", p)
                    r2 = re.search("(.*).*\(.*\)",r.group(1))
                    if r2:
                        loc = r2.group(1).strip()
                        loc2 = r.group(1).strip()
                    else:
                        loc = r.group(1).strip()
                        loc2  = r.group(1).strip()
            putRow(csv, asset["id"], asset["hostIp"], asset["hostPrimaryName"].lower(), corename.lower().strip(), asset["systemType"],
                loc, loc2, asset['routingRulesCount'],
                asset['creationDate'],  asset['modificationDate'], asset['createdBy'], asset['modifiedBy'],
                cmdbid)
            ids[id_] = True
    return

def setDebug():
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })
    
def initOutput(*args):
    h = csv.writer(sys.stdout)
    if not cfg.noheader:
        h.writerow(args)
    return(h)
    
def putRow(h, *args):
    h.writerow(args)

def closeOutput(h):
    Noop

p = configargparse.getArgumentParser(add_help=None, default_config_files=[SCRIPTDIR + '/sbcli.ini', '/etc/fcp/sbcli.ini', '~/.fcp/sbcli.ini'])
p.add('-f', '--config',                 metavar='CONFIGFILE', required=None, is_config_file=True, help='Config file')   
p.add(      '--url',                    dest='url', metavar='URL', help='URL of Skybox server', default=None, required=True)
p.add(      '--user',                   dest='user', metavar='USER', help='User on skybox server', default=None, required=True)
p.add(      '--password',               dest='password', metavar='PW', help='Password on skybox server', default=True, required=True)
p.add(      '--cache',                  dest='cache', metavar='FILE', help='Use cache for sbox requests', default=None)
p.add(      '--crt',                    dest='crt',type=str, help='Skybox cert file', default=None)
p.add(      '--iprange',                dest='iprange', metavar='IP', help='IP Range')
p.add(      '--matching-networks',      dest='matchingnetworks', action='store_const', const='matchingnetworks', metavar='Bool', default=None, help='Return not only strict ipranges but matching networks too')
p.add(      '--ip',                     dest='ip', action='append', metavar='IP', help='IP')
p.add(      '--netname',                dest='netname', metavar='Name', help='Network Name')
p.add(      '--nettype',                dest='nettype', metavar='Type', help='Network Type', choices=["Regular","Perimeter Cloud"])
p.add(      '--location',               dest='location', metavar='Name', help='Location Name')
p.add(      '--locationid',             dest='locationid', metavar='ID', help='Location ID')
p.add(      '--fromip',                 dest='fromip',  action='append', metavar='IP', help='IP From')
p.add(      '--fromnetid',              dest='fromnetid',  metavar='NetId', help='Network Id From')
p.add(      '--tonetid',                dest='tonetid',  metavar='NetId', help='Network Id To')
p.add(      '--amode',                  dest='amode', metavar='AccessQueryMode', help='AccessQueryMode', choices=["Accessible","Inaccessible","Both"], default="Accessible")
p.add(      '--aoutput',                dest='aoutput', metavar='AccessQueryOutput', help='AccessQueryOutput', choices=["xml","csv","trace","exposed"], default="trace")
p.add(      '--ainput',                 dest='ainput', metavar='AccessQueryInput', help='AccessQueryInput XML')
p.add(      '--toip',                   dest='toip',  action='append', metavar='IP', help='IP To')
p.add(      '--ports',                  dest='ports',  action='append', metavar='NUM[/TCP/UDP]', help='Ports')
p.add(      '--maxaclobjects',          dest='maxaclobjects',  type=int, metavar='MAX', help='Maximum objects in source or destination of acl to process', default=10)
p.add(      '--hostname',               dest='hostname', metavar='Host', action='append', help='Host to set attributes')
p.add(      '--hostid',                 dest='hostid', metavar='HostId', action='append', help='Hostid to set attributes')
p.add(      '--custom-field',           dest='cf', metavar='CF=value', action='append', help='Set custom field')
p.add(      '--tanalysisid',            dest='tanalysisid', metavar='ID', help='Ticket analysis id to find')
p.add(      '--ticketid',               dest='ticketid', metavar='ID', help='Ticket id to find/update')
p.add(      '--ticket-status',          dest='ticket_statuses', metavar='Ticket Status[es]', help='Separated by coma', default='New,InProgress,Resolved,Closed,Rejected,Verified,Ignored,Reopened')
p.add(      '--tickets-listonly',       dest='tickets_listonly', action='store_const', const='tickets_listonly', metavar='Bool', default=None, help='List only basic ticket info')
p.add(      '--externalid',             dest='externalid', metavar='ID', help='External ticket id')
p.add(      '--table',                  dest='table', metavar='Table name', help='Table name to load from CSV')
p.add(      '--table-csv',              dest='tablecsv', metavar='CSV', help='CSV file to load')
p.add(      '--description',            dest='description', metavar='STR', help='Description of ticket')
p.add(      '--owner',                  dest='owner', metavar='Owner', help='Set owner')
p.add(      '--site',                   dest='site', metavar='Site', help='Set site')
p.add(      '--comment',                dest='comment', metavar='Comment', help='Set comment')
p.add(      '--taskid',                 dest='taskid', metavar='TASKID', help='Taskid for operation')
p.add(      '--type',                   dest='type', metavar='HOSTTYPE', help='Hosts types to search')
p.add(      '--esurl',                  dest='esurl', help='Elastic url')
p.add(      '--esuser',                 dest='esuser',type=str, help='Elastic user')
p.add(      '--espass',                 dest='espass',type=str, help='Elastic pass')
p.add(      '--escrt',                  dest='escrt',type=str, help='Elastic cert file')
p.add(      '--esquery',                dest='esquery',type=str, help='Elastic query')
p.add(      '--date',                   dest='date', help='Date to search in index', type=str)
p.add(      '--cmdbidattr',             dest='cmdbidattr',type=str, help='CMDB id business attribute name', default="u_sys_id")
p.add(      '--mysqluser',              dest='mysqluser',type=str, help='Mysql user', default='skyboxview')
p.add(      '--mysqlpass',              dest='mysqlpass',type=str, help='Mysql pass', default='skyboxview')
p.add(      '--mysqlhost',              dest='mysqlhost',type=str, help='Mysqlhost', default='127.0.0.1')
p.add(      '--mysqlport',              dest='mysqlport',type=str, help='Mysqlport', default='3306')
p.add(      '--ssl-no-verify',          dest='sslnoverify', action='store_const', const='sslnoverify', metavar='Bool', help='Do not verify SSL', default=None)
p.add(      '--noheader',               dest='noheader', action='store_const', const='noheader', metavar='Bool', help='Do not write CSV header', default=None)
p.add('-h',                             dest='help', action='store_const', const='help', metavar='Bool', help='Help', default=None)
p.add('-d',                             dest='d', action='store_const', const='d', metavar='Bool', default=None)
p.add('cmd',                            choices=sorted(['listMethods', 'listTasks', 'listTaskIPs',
                                            'findAssetsByLocation', 'findAllAssets', 'findLocations', 
                                            'listCustomFields', 'getHostAttributes','getHostCluster', 'getHostInterfaces',
                                            'findAssetsByIps', 'findTickets', 'listAnalysis', 'getTicket', 'getAccessRequestsPerTicket', 'getHistoryPerTicket', 'getChangeRequestsPerTicket',
                                            'findFwChanges',
                                            'findRoute', 'listFirewallsWithoutZones', 'findAclsByIpRange',
                                            'findNetworksByIpRange',
                                            'findNetworksByName',
                                            'findNetworksByLocation',
                                            'findMissingNeighbors',
                                            'findNetworksInPerimeterCloud',
                                            'findNetworkIssues',
                                            'checkAccessV3',
                                            'updateHostAttributes',
                                            'findAssetsByNames',
                                            'findFirewallsByName',
                                            'IpRangeToIps',
                                            'siteMap',
                                            'loadCsv',
                                            'testSwagger',
                                            'updateAccessChangeTicket',
                                            'help']), help='Command to execute.')
cfg = p.parse_args()

if cfg.d:
    setDebug()

if cfg.fromip and re.match(".*,.*", cfg.fromip[0]):
    cfg.fromip = cfg.fromip[0].split(",")

if cfg.toip and re.match(".*,.*", cfg.toip[0]):
    cfg.toip = cfg.toip[0].split(",")

if cfg.help or cfg.cmd=='help':
    helpMsg(p)

if cfg.cf:
    cf = {}
    for c in cfg.cf:
        r = re.match("(.*)=(.*)", c)
        if r:
            cf[r.group(1)]=r.group(2)
        else:
            logging.error("Customfield not in format var=value!")
            sys.exit(2)
    cfg.cf = cf
    
if cfg.cache:
    requests_cache.install_cache(cfg.cache)
    #expire_after = datetime.timedelta(hours=4)
    requests_cache.install_cache()
    requests_cache.remove_expired_responses()

if not cfg.date:
    cfg.date=datetime.now().strftime("%Y.%m.%d")
else:
    date = arrow.get(cfg.date).datetime
    cfg.date = date.strftime("%Y.%m.%d")

session = requests.Session()
session.verify = cfg.crt
session.auth = requests.auth.HTTPBasicAuth(cfg.user, cfg.password)
transport = zeep.Transport(session=session)
client = zeep.Client(cfg.url + '/skybox/webservice/jaxws/network?wsdl', transport=transport)
client_tickets = zeep.Client(cfg.url + '/skybox/webservice/jaxws/tickets?wsdl', transport=transport)
client_fwchanges = zeep.Client(cfg.url + '/skybox/webservice/jaxws/firewallchanges?wsdl', transport=transport)

if cfg.cmd=='findNetworksByIpRange':
    if not cfg.iprange:
        print("Missing iprange arg")
        sys.exit(1)
    else:
        csv = initOutput('id', 'net', 'ip','length', 'name','location','type')
        ips = client.service["findNetworks"](ipRange=cfg.iprange)
        iprange = ipaddress.IPv4Network(cfg.iprange)
        any=ipaddress.IPv4Network("0.0.0.0/0")
        for ip in ips.netElements:
            net = ipaddress.IPv4Network(ip["IPAddress"]+"/"+str(ip["netMask"]))
            if cfg.matchingnetworks:
                putRow(csv, ip["id"],net,ip["IPAddress"],ip["netMask"],ip["name"],ip["path"],ip["type"])
            else:
                if iprange.overlaps(net) and net!=any:
                    putRow(csv, ip["id"],net,ip["IPAddress"],ip["netMask"],ip["name"],ip["path"],ip["type"])

elif cfg.cmd=='findMissingNeighbors':
    mn = findMissingNeighbors()
    csv = initOutput('missing', 'abicount', 'viewed', 'hostIp', 'hostname', 'ipmask', 'networkGUIName', 'date', 'connectivityIssue', 'type')
    for r in mn:
        putRow(csv, mn[r]['ip'], ";".join(set(mn[r]['ipRangesOfAddrsBehindCount'])), mn[r]['viewed'], ";".join(set(mn[r]['hostIp'])), ";".join(set(mn[r]['hostName'])), mn[r]['ipmask'], mn[r]['networkGUIName'], mn[r]['exportDate'], mn[r]['connectivityIssue'], ";".join(set(mn[r]['type'])))

elif cfg.cmd=='findNetworkIssues':
    ni = findNetworkIssues()
    csv = initOutput('id', 'abicount', 'viewed', 'hostIp', 'hostname', 'networkGUIName', 'ipmask', 'date', 'connectivityIssue', 'type')
    for r in ni:
        putRow(csv, ni[r]['id'], ni[r]['ipRangesOfAddrsBehindCount'], ni[r]['viewed'], ni[r]['hostIp'], ni[r]['hostName'], ni[r]['networkGUIName'], ni[r]['ipmask'], ni[r]['exportDate'], ni[r]['connectivityIssue'], ni[r]['type'])

elif cfg.cmd=='findRoute':
    if not cfg.iprange:
        print("Missing iprange arg")
        sys.exit(1)
    else:
        iprange=ipaddress.ip_network(cfg.iprange)
        routes = findRouteByIpRange(iprange)
        csv = initOutput('id','gw','type','hostname','date')
        for r in routes:
            putRow(csv, r['id'],r['gatewayIPAddresses'][0],r['hostTypeEnum'],r['hostName'],r['exportDate'])
        #sys.exit()

elif cfg.cmd=='findAssetsByIps':
    if not cfg.ip:
        print("Missing IP arg")
        sys.exit(1)
    else:
        ips = findAssetsByIps(client, cfg.ip)
        csv = initOutput('id','ip','name','type','os','routingRules')
        for ip in ips:
            putRow(csv, ips[ip]["id"],ips[ip]["primaryIp"],ips[ip]["name"],ips[ip]["type"],ips[ip]["os"], ips[ip]['routingRules'])

elif cfg.cmd=='findNetworksByName':
    if not cfg.netname:
        print("Missing netname arg")
        sys.exit(1)
    else:
        ips = findNetworksByName(cfg.netname, cfg.nettype)
        csv = initOutput('id','ip','name','location')
        for ip in ips:
            putRow(csv, ips[ip]["id"],ips[ip]["ip"],ips[ip]["name"])

elif cfg.cmd=='findNetworksByLocation':
    if not cfg.location and not cfg.locationid:
        print("Missing location or locationid arg")
        sys.exit(1)
    else:
        csv = initOutput('id','ip','name','location')
        if cfg.location:
            ips = findNetworksByLocation(cfg.location, cfg.nettype)
        else:
            ips = findNetworksByLocationId(cfg.locationid, cfg.nettype)
        for ip in ips:
            putRow(csv, ips[ip]["id"],ips[ip]["ip"],ips[ip]["name"],ips[ip]["location"])

elif cfg.cmd=='findLocations':
    csv = initOutput('id','name','path')
    locs = findLocations()
    for l in locs:
            putRow(csv, locs[l]["id"], locs[l]["name"], locs[l]["location"])

elif cfg.cmd=='findAclsByIpRange':
    if not cfg.fromip and not cfg.toip:
        logging.error("Need fromip and/or toip!")
        sys.exit(2)
    else:
        if cfg.fromip:
            f = cfg.fromip
        else:
            f = [None]
        if cfg.toip:
            t = cfg.toip
        else:
            t = [None]
        if not cfg.esquery:
            cfg.esquery="actionEnum: Allow"
        csv = initOutput('id', 'host', 'iface', 'chain', 'src', 'dst', 'action')
        all = {}
        for f_ in f:
            for t_ in t:
                all.update(findAclsByIpRange(f_, t_, cfg.esquery))
        for a in all:
            putRow(csv, all[a]["id"], all[a]["hostName"], ";".join(all[a]["sourceNetworkInterfaces"]),
                ";".join(all[a]["sourceAddresses"]), ";".join(all[a]["destinationAddresses"]),
                   all[a]["actionEnum"])

elif cfg.cmd=='findAllAssets':
    assets = findAllAssets(cfg.esquery)
    postProcessAssets(assets)
    
elif cfg.cmd=='findAssetsByLocation':
    if not cfg.location and not cfg.locationid:
        print("Missing location or locationid arg")
        sys.exit(1)
    else:
        if not cfg.location:
            if cfg.locationid:
                cfg.location = getLocation(cfg.locationid)            
        logging.warning("Searching assets in locationid %s" % (cfg.location))
        assets = findAssetsByLocation(cfg.location)
        postProcessAssets(assets)

elif cfg.cmd=='findNetworksInPerimeterCloud':
    if not cfg.netname:
        logging.error("Need netname!")
        sys.exit(2)
    else:
        ips = findNetworksInPerimeterCloud(cfg.netname)
        csv = initOutput('ipnet')
        for ip in ips:
            putRow(csv, ips[ip])

elif cfg.cmd=='findTickets':
    f = {
        'myGroups': False,
        'createdBy': '',
        'modifiedBy': '',
        'phaseName': '',
        'owner': '',
        'freeTextFilter': '',
        'statusFilter': cfg.ticket_statuses.split(",")
    }
    logging.warning("Searching for tickets (status %s)" % (cfg.ticket_statuses))
    tickets = client_tickets.service['findAccessChangeTickets'](filter=f)
    csv = initOutput('id', 'createdBy', 'creationTime', 'externalTicketId', 'externalTicketStatus', 'likelihood', 'priority', 'status', 'title', 'risk', 'compliance')
    for t in tickets:
        if t['creationTime'].date()>=datetime.date(date):
            changes=[]
            if cfg.tickets_listonly:
                severity = 'unknown'
                importance = 'unknown'
            else:
                for x in range(1, 10):
                    try:
                        changes = getChangeRequestsPerTicket(t['id'])
                    except zeep.exceptions.Fault as error:
                        logging.error("Loop %s: %s" % (x, error))
                        time.sleep(10)
                    if len(changes)>0:
                        logging.debug("Got info about ticket %s" % (t['id']))
                        severity = changes[0]['severity']
                        importance = changes[0]['importance']
                        break;
                    else:
                        severity = 'NA'
                        importance = 'NA'
            putRow(csv, t['id'], t['createdBy'], t['creationTime'], t['externalTicketId'], t['likelihood'], t['priority'], t['externalTicketStatus'], t['status'], t['title'], severity, importance)

elif cfg.cmd=='findAssetsByNames':
    results = findAssetsByNames(client, cfg.hostname)
    csv = initOutput('id','ip','name','os')
    for h in results:
        putRow(csv, h , results[h]['name'], results[h]['primaryIp'], results[h]['os'])

elif cfg.cmd=='findFirewallsByName':
    results = {}
    for h in cfg.hostname:
        result = client.service[cfg.cmd](name=h)
        if result.status.code != 0:
            print("Bad status code! Exiting")
            print(result.status)
            sys.exit(2)
        else:
            csv = initOutput('id','name','path')
            if len(result.fwElements)>0:
                for i in result.fwElements:
                    results[i.id] = i
    for h in results:
        putRow(csv, h, results[h]['id'], results[h]['name'], results[h]['path'])
        
elif cfg.cmd=='getHostAttributes':
    if not cfg.hostname:
        print("Missing hostname")
        sys.exit(1)
    if cfg.hostname:
        hostIds = list(findAssetsByNames(client, cfg.hostname).keys())
    elif cfg.hostid:
        hostIds = cfg.hostid
    if len(hostIds)!=1:
         print("More ore none result! Need one hostname/id!")
         sys.exit(2)
    attributes = client.service['getHostAttributes'](hostIds[0])
    csv = initOutput('name','value')
    for a in attributes:
        if a=='email' or a=='owner' or a=='userComment' or a=='businessFunction' or a=='site':
            putRow(csv, a, attributes[a])
    for a in attributes['customFields']:
        putRow(csv, a['name'],a['value'])

elif cfg.cmd=='getHostInterfaces':
    if not cfg.hostname and not cfg.hostid:
        print("Missing hostname or hostid")
        sys.exit(1)
    if cfg.hostname:
        hosts = findAssetsByNames(client, cfg.hostname)
        if len(hosts)==0:
            print("No hosts.")
            sys.exit(2)
    if len(hosts)!=1:
        print("More ore none result! Need one hostname/id!")
        sys.exit(2)
    csv = initOutput('id','ip','name','description','type')
    for h in hosts.keys():
        for i in hosts[h]['netInterface']:
            putRow(csv, i['id'], i['ipAddress'], i['name'],i['description'], i['type'])

elif cfg.cmd=='getHostCluster':
    if not cfg.hostname:
        print("Missing hostname")
        sys.exit(1)
    if cfg.hostname:
        hostIds = list(findAssetsByNames(client, cfg.hostname).keys())
        if len(hostIds)==0:
            print("No hosts.")
            sys.exit(2)
    elif cfg.hostid:
        hostIds = cfg.hostid
    csv = initOutput('id', 'name', 'type')
    for c in hostIds:
        cl = client.service['getHostCluster'](hostId=c)
        if cl:
            putRow(csv, cl['id'], cl['name'], cl['type'])
        
elif cfg.cmd=='getTicket':
    if not cfg.ticketid:
        logging.error("Need ticketid!")
        sys.exit(2)
    ticket = client_tickets.service['getAccessChangeTicket'](ticketId=cfg.ticketid)
    csv = initOutput('ticketId', 'changeId', 'sourceAddresses', 'destinationAddresses', 'accessStatus', 'accessType', 'comment', 'complianceStatus', 'potentialVulnerabilities')
    for t in changes:
        putRow(csv, cfg.ticketid, t['id'], t['accessStatus'], " ".join(t['accessQuery']['sourceAddresses']), " ".join(t['accessQuery']['destinationAddresses']), t['accessType'], t['comment'], t['complianceStatus'], len(t['potentialVulnerabilities']))

elif cfg.cmd=='getAccessRequestsPerTicket':
    if not cfg.ticketid:
        logging.error("Need ticketid!")
        sys.exit(2)
    changes = client_tickets.service['getTicketAccessRequests'](ticketId=cfg.ticketid)
    csv = initOutput('ticketId', 'changeId', 'sourceAddresses', 'destinationAddresses', 'accessStatus', 'accessType', 'comment', 'complianceStatus', 'potentialVulnerabilities')
    for t in changes:
        putRow(csv, cfg.ticketid, t['id'], t['accessStatus'], " ".join(t['accessQuery']['sourceAddresses']), " ".join(t['accessQuery']['destinationAddresses']), t['accessType'], t['comment'], t['complianceStatus'], len(t['potentialVulnerabilities']))

elif cfg.cmd=='getChangeRequestsPerTicket':
    if not cfg.ticketid:
        logging.error("Need ticketid!")
        sys.exit(2)
    changes = getChangeRequestsPerTicket(cfg.ticketid)
    csv = initOutput('ticketId', 'changeId', 'sourceAddresses', 'destinationAddresses', 'complianceStatus', 'risk', 'compliance')
    for t in changes:
        putRow(csv, cfg.ticketid, t['id'], " ".join(t['sourceAddresses']), " ".join(t['destinationAddresses']), t['complianceStatus'], t['severity'], t['importance'])

elif cfg.cmd=='getHistoryPerTicket':
    if not cfg.ticketid:
        logging.error("Need ticketid!")
        sys.exit(2)
    changes = client_tickets.service['getTicketEvents'](ticketId=cfg.ticketid)
    csv = initOutput('ticketId', 'changeId', 'sourceAddresses', 'destinationAddresses', 'accessStatus', 'accessType', 'comment', 'complianceStatus', 'potentialVulnerabilities')
    print(changes)
    sys.exit()
    for t in changes:
        putRow(csv, cfg.ticketid, t['id'], t['accessStatus'], " ".join(t['accessQuery']['sourceAddresses']), " ".join(t['accessQuery']['destinationAddresses']), t['accessType'], t['comment'], t['complianceStatus'], len(t['potentialVulnerabilities']))

elif cfg.cmd=='checkAccessV3':
    if not cfg.ainput:
        logging.warning("Running access query...")
        srcel = ipsToEl(cfg.fromip, cfg.fromnetid)
        dstel = ipsToEl(cfg.toip, cfg.tonetid)
        result = aQuery(srcel, dstel, cfg)
        if result:
            xml = result.replace("<![CDATA[", "").replace("]]>", "")
        else:
            logging.error("No path found!")
            sys.exit(2)
    else:
        with open(cfg.ainput,"r") as ainput:
            xml = ainput.read()
    if cfg.aoutput == "trace":
        parseAqResultTrace(xml)
    elif cfg.aoutput == "xml":
        print(xml)
    elif cfg.aoutput == "exposed":
        parseAqResultExposed(xml)
    else:
        logging.error("Bad output mode")
        sys.exit(2)

elif cfg.cmd=='listMethods':
    print("Network APIs")
    listMethods(client)
    print("Tickets APIs")
    listMethods(client_tickets)
    print("Firewall changes APIs")    
    listMethods(client_fwchanges)
    sys.exit()

elif cfg.cmd=='listTasks':
    logging.warning("Listing tasks")
    m = mysqlConnect('skyboxview_core', cfg)
    cursor = m.cursor()
    cursor.execute("SELECT id AS id_,name,creation_time,last_modification_time,modified_by,started_in,finished_in,exit_code FROM sbv_task_definitions")
    csv = initOutput('id','name','creation_time','last_modification_time', 'modified_by', 'started_in', 'finished_in', 'exit_code')
    for (id_, name, creation_time, last_modification_time, modified_by, started_in, finished_in, exit_code) in cursor:
        putRow(csv, id_, name, creation_time, last_modification_time, modified_by, started_in, finished_in, exit_code)
    sys.exit()

elif cfg.cmd=='listTaskIPs':
    if not cfg.taskid:
        print("Missing taskid arg")
        sys.exit(1)
    logging.warning("Listing task IPs for task %s" % (cfg.taskid))
    m = mysqlConnect('skyboxview_core', cfg)
    cursor = m.cursor()
    cursor.execute("SELECT d.name AS name, d.id AS id_, p.value_ AS ips FROM sbv_task_properties p, sbv_task_definitions d WHERE d.id=%s AND p.task_definition_id=%s AND p.value_ regexp '^([0-9]*)\\\\.([0-9]*)' limit 10;" % (cfg.taskid, cfg.taskid))
    csv = initOutput('id', 'name', 'ip', 'inmodel')
    for (name, id_, ips) in cursor:
        iparr = ips.split(",")
        for ip in iparr:
            ips2 = IpRangeToIps(ip.strip())
            for ip2 in ips2:
                assets = findAssetsByIps(client, [ip2])
                hosts=[]
                for a in assets:
                    hosts.append(assets[a]['name'])
                putRow(csv, id_, name, str(ip2).split("/")[0], ";".join(hosts))
    sys.exit()

elif cfg.cmd=='listCustomFields':
    defIds = client.service['getHostEntityFields']()
    for d in defIds:
        print(d['name'], d['entityType'])
                
elif cfg.cmd=='listAnalysis':
    analysis = client_tickets.service['getAnalysisTree'](type='Network Assurance Tickets Public')
    print(analysis)

elif cfg.cmd=='listFirewallsWithoutZones':
    hosts = findFirewallsWithoutZones()
    csv = initOutput('id', 'name')
    for id in hosts:
        putRow(csv, id, hosts[id])
    sys.exit()

elif cfg.cmd=='findFwChanges':
    changes = client_fwchanges.service['findFirewallChanges'](arg0={ 'trackingPeriod': {'startDate': arrow.get(cfg.date).datetime, 'endDate': datetime.utcnow()}, 'firewallId': 1, 'folderId': 1})

    csv = initOutput('availabilityImpact','changeReconciliationCoverage','changeReconciliationStatus','changeState','changeTime','changeType','changedBy','comment','configurationChangeTime','createdBy','creationTime','description','entityName','firewallType','hostId','hostIpAddress','hostName','id','lastModificationTime','lastModifiedBy','lastReviewer','ticketByComment', 'affectedRuleIds', 'failedRuleIds', 'accessCompliance', 'ruleCompliance')
    for t in changes:
        affectedruleids = []
        failedruleids = []
        accesscompliance = "Passed"
        rulecompliance = "Passed"
        if t['changeType'] == 'OBJECT':
            if t['changeState'] == 'DELETED':
                accesscompliance = 'N/A'
                rulecompliance = 'N/A'
            else:
                r  = re.match('^Object (.*)', t['entityName'])
                if r:
                    object = r.group(1)
                    rules = findRuleByObject(object)
                    for a in rules:
                        if a not in affectedruleids:
                            affectedruleids.append(a)
                        if rules[a]["RuleCompliance"] == "Failed":
                            rulecompliance = "Failed"
                            if a not in failedruleids:
                                failedruleids.append(a)
                        if rules[a]["FAAccessCompliance"] == "Failed":
                            accesscompliance = "Failed"
                            if a not in failedruleids:
                                failedruleids.append(a)
                else:
                    logging.warning("Object %s not found!" %(t['entityName']))
                    accesscompliance = 'N/F'
                    rulecompliance = 'N/F'
        if t['changeType'] == 'ACL':
            if t['changeState'] == 'DELETED':
                accesscompliance = 'N/A'
                rulecompliance = 'N/A'
            else:
                r  = re.match('^Rule #(.*) ', t['entityName'])
                if r:
                    acl = r.group(1)
                    rules = getRuleById(t['hostId'], acl)
                    if len(rules)==0:
                        logging.warning("ACL %s on host %s not found!" % (t['entityName'], t['hostId']))
                        accesscompliance = 'N/F'
                        rulecompliance = 'N/F'
                    for a in rules:
                        if a not in affectedruleids:
                            affectedruleids.append(a)
                        if rules[a]["RuleCompliance"] == "Failed":
                            rulecompliance = "Failed"
                            if a not in failedruleids:
                                failedruleids.append(a)
                        if rules[a]["FAAccessCompliance"] == "Failed":
                            accesscompliance = "Failed"
                            if a not in failedruleids:
                                failedruleids.append(a)
                else:
                    logging.warning("ACL %s not found!" %(t['entityName']))
                    accesscompliance = 'N/F'
                    rulecompliance = 'N/F'
        putRow(csv, t['availabilityImpact'], t['changeReconciliationCoverage'], t['changeReconciliationStatus'], t['changeState'], \
        t['changeTime'], t['changeType'], t['changedBy'], t['comment'], t['configurationChangeTime'], t['createdBy'], t['creationTime'], t['description'], t['entityName'], t['firewallType'], t['hostId'], t['hostIpAddress'], \
        t['hostName'], t['id'], t['lastModificationTime'], t['lastModifiedBy'], t['lastReviewer'], t['ticketByComment'], " ".join(affectedruleids), " ".join(failedruleids), accesscompliance, rulecompliance)
    sys.exit()
    
elif cfg.cmd=='testSwagger':
    http_client = RequestsClient(ssl_verify=False)
    u = urllib.parse.urlparse(cfg.url)
    http_client.set_basic_auth(
        u.hostname, cfg.user, cfg.password
    )
    swurl = u.scheme + '://' + u.netloc + urllib.parse.urljoin(u.netloc,'/skybox/webservice/jaxrs/swagger.json')
    client = SwaggerClient.from_url(
        swurl,
        http_client=http_client,
    )
    print(client)
    sys.exit()       
        
elif cfg.cmd=='updateHostAttributes':
    if (not cfg.comment and not cfg.cf and not cfg.owner and not cfg.site) or (not cfg.hostname and not cfg.hostid):
        print("Missing parameter to change or hostid or hostname.")
        sys.exit(1)
    else:
        defIds = client.service['getHostEntityFields']()
        if cfg.hostname:
            hostIds = list(findAssetsByNames(client, cfg.hostname).keys())
            if len(hostIds)==0:
                print("No hosts to update.")
                sys.exit(2)
        elif cfg.hostid:
            hostIds = cfg.hostid
        logging.warning("Updating host attributes for host %s" % (hostIds))
        data={
            'hostAttributes': {},
            'hostIds': hostIds,
            }
        if cfg.comment:
            data['hostAttributes']['userComment'] = cfg.comment
        if cfg.cf:
            data['hostAttributes']['customFields'] = list()
            for name in cfg.cf.keys():
                value = cfg.cf[name]
                found = None
                for d in defIds:
                    if d['name'] == name:
                        data['hostAttributes']['customFields'].append( {'defId': d['defId'], 'id': d['id'], 'entityType': d['entityType'], 'name': name, 'value': value} )
                        found = True
                if not found:
                    logging.error("Custom attribute %s not found!" % (name))
                    sys.exit(2)
        if cfg.owner:
            data['hostAttributes']['owner'] = cfg.owner
        if cfg.site:
            data['hostAttributes']['site'] = cfg.site
        #print(data,hostIds)
        result = client.service[cfg.cmd](updateInfo=data)
        logging.warning("OK (%s)" % result.results)
        sys.exit()

elif cfg.cmd=='updateAccessChangeTicket':
    if (not cfg.externalid) or (not cfg.ticketid):
        print("Missing ticketid and externalid")
        sys.exit(1)
    else:
        ticket={}
        for x in range(1, 10):
            try:
                ticket = getAccessChangeTicket(cfg.ticketid)
            except zeep.exceptions.Fault as error:
                logging.error("Loop %s: %s" % (x, error))
                time.sleep(10)
            if len(ticket)>0:
                logging.debug("Got info about ticket %s" % (cfg.ticketid))
                break;

        if len(ticket)==0:
            logging.error("Did not fetch ticket data")
            sys.exit(2)
        logging.warning("Updating ticket attributes for ticket %s" % (cfg.ticketid))
        ticket['externalTicketId'] = cfg.externalid
        result = client_tickets.service[cfg.cmd](accessChangeTicket=ticket)
        logging.warning("OK (%s)" % result.id)
        sys.exit()

elif cfg.cmd=="IpRangeToIps":
    print(IpRangeToIps(cfg.iprange))


