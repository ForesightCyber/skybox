## Skybox cli utility

```
usage: sbcli.py [-f CONFIGFILE] --url URL --user USER --password PW
                [--cache FILE] [--crt CRT] [--iprange IP]
                [--matching-networks] [--ip IP] [--netname Name]
                [--nettype Type] [--location Name] [--locationid ID]
                [--fromip IP] [--fromnetid NetId] [--tonetid NetId]
                [--amode AccessQueryMode] [--aoutput AccessQueryOutput]
                [--ainput AccessQueryInput] [--toip IP]
                [--ports NUM[/TCP/UDP]] [--maxaclobjects MAX]
                [--hostname Host] [--hostid HostId] [--custom-field CF=value]
                [--tanalysisid ID] [--ticketid ID] [--externalid ID]
                [--table Table name] [--table-csv CSV] [--description STR]
                [--owner Owner] [--site Site] [--comment Comment]
                [--taskid TASKID] [--type HOSTTYPE] [--esurl ESURL]
                [--esuser ESUSER] [--espass ESPASS] [--escrt ESCRT]
                [--esquery ESQUERY] [--date DATE] [--cmdbidattr CMDBIDATTR]
                [--mysqluser MYSQLUSER] [--mysqlpass MYSQLPASS]
                [--mysqlhost MYSQLHOST] [--mysqlport MYSQLPORT]
                [--ssl-no-verify] [--noheader] [-h] [-d]
                {IpRangeToIps,checkAccessV3,findAclsByIpRange,findAllAssets,findAssetsByIps,findAssetsByLocation,findAssetsByNames,findFirewallsByName,findLocations,findMissingNeighbors,findNetworkIssues,findNetworksByIpRange,findNetworksByLocation,findNetworksByName,findNetworksInPerimeterCloud,findRoute,findTickets,getAccessRequestsPerTicket,getChangeRequestsPerTicket,getHistoryPerTicket,getHostAttributes,getHostCluster,getHostInterfaces,getTicket,help,listAnalysis,listCustomFields,listFirewallsWithoutZones,listMethods,listTaskIPs,listTasks,loadCsv,siteMap,testSwagger,updateAccessChangeTicket,updateHostAttributes}

Args that start with '--' (eg. --url) can also be set in a config file
(/home/lm/bin/sbcli.ini or /etc/fcp/sbcli.ini or ~/.fcp/sbcli.ini or specified
via -f). Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for
details, see syntax at https://goo.gl/R74nmi). If an arg is specified in more
than one place, then commandline values override config file values which
override defaults.

positional arguments:
  {IpRangeToIps,checkAccessV3,findAclsByIpRange,findAllAssets,findAssetsByIps,findAssetsByLocation,findAssetsByNames,findFirewallsByName,findLocations,findMissingNeighbors,findNetworkIssues,findNetworksByIpRange,findNetworksByLocation,findNetworksByName,findNetworksInPerimeterCloud,findRoute,findTickets,getAccessRequestsPerTicket,getChangeRequestsPerTicket,getHistoryPerTicket,getHostAttributes,getHostCluster,getHostInterfaces,getTicket,help,listAnalysis,listCustomFields,listFirewallsWithoutZones,listMethods,listTaskIPs,listTasks,loadCsv,siteMap,testSwagger,updateAccessChangeTicket,updateHostAttributes}
                        Command to execute.

optional arguments:
  -f CONFIGFILE, --config CONFIGFILE
                        Config file (default: None)
  --url URL             URL of Skybox server (default: None)
  --user USER           User on skybox server (default: None)
  --password PW         Password on skybox server (default: True)
  --cache FILE          Use cache for sbox requests (default: None)
  --crt CRT             Skybox cert file (default: None)
  --iprange IP          IP Range (default: None)
  --matching-networks   Return not only strict ipranges but matching networks
                        too (default: None)
  --ip IP               IP (default: None)
  --netname Name        Network Name (default: None)
  --nettype Type        Network Type (default: None)
  --location Name       Location Name (default: None)
  --locationid ID       Location ID (default: None)
  --fromip IP           IP From (default: None)
  --fromnetid NetId     Network Id From (default: None)
  --tonetid NetId       Network Id To (default: None)
  --amode AccessQueryMode
                        AccessQueryMode (default: Accessible)
  --aoutput AccessQueryOutput
                        AccessQueryOutput (default: trace)
  --ainput AccessQueryInput
                        AccessQueryInput XML (default: None)
  --toip IP             IP To (default: None)
  --ports NUM[/TCP/UDP]
                        Ports (default: None)
  --maxaclobjects MAX   Maximum objects in source or destination of acl to
                        process (default: 10)
  --hostname Host       Host to set attributes (default: None)
  --hostid HostId       Hostid to set attributes (default: None)
  --custom-field CF=value
                        Set custom field (default: None)
  --tanalysisid ID      Ticket analysis id to find (default: None)
  --ticketid ID         Ticket id to find/update (default: None)
  --externalid ID       External ticket id (default: None)
  --table Table name    Table name to load from CSV (default: None)
  --table-csv CSV       CSV file to load (default: None)
  --description STR     Description of ticket (default: None)
  --owner Owner         Set owner (default: None)
  --site Site           Set site (default: None)
  --comment Comment     Set comment (default: None)
  --taskid TASKID       Taskid for operation (default: None)
  --type HOSTTYPE       Hosts types to search (default: None)
  --esurl ESURL         Elastic url (default: None)
  --esuser ESUSER       Elastic user (default: None)
  --espass ESPASS       Elastic pass (default: None)
  --escrt ESCRT         Elastic cert file (default: None)
  --esquery ESQUERY     Elastic query (default: None)
  --date DATE           Date to search in index (default: None)
  --cmdbidattr CMDBIDATTR
                        CMDB id business attribute name (default: u_sys_id)
  --mysqluser MYSQLUSER
                        Mysql user (default: skyboxview)
  --mysqlpass MYSQLPASS
                        Mysql pass (default: skyboxview)
  --mysqlhost MYSQLHOST
                        Mysqlhost (default: 127.0.0.1)
  --mysqlport MYSQLPORT
                        Mysqlport (default: 3306)
  --ssl-no-verify       Do not verify SSL (default: None)
  --noheader            Do not write CSV header (default: None)
  -h                    Help (default: None)
  -d

Command Line Args:   -f sbcli.ini.dist help
Config File (sbcli.ini.dist):
  url:               https://<host>:8443/
  user:              <user>
  password:          <pass>
  ssl-no-verify:     True
  esurl:             https://<host>:9201/
  esuser:            <user>
  espass:            <pass>
  escrt:             elk.crt
  mysqluser:         <user>
  mysqlpass:         <pass>
  mysqlhost:         127.0.0.1
  mysqlport:         3306
Defaults:
  --amode:           Accessible
  --aoutput:         trace
  --maxaclobjects:   10
  --cmdbidattr:      u_sys_id

```
