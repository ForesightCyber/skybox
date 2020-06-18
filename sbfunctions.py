
import logging
import mysql.connector
import sys
import time
from xml.parsers import expat

def mysqlConnect(db, cfg):
    mydb = mysql.connector.connect(
                                   host=cfg.mysqlhost,
                                   port=cfg.mysqlport,
                                   user=cfg.mysqluser,
                                   passwd=cfg.mysqlpass,
                                   database=db
                                   )
    return(mydb)

# Parse XML of accss query result
class parseAqResultTrace():
    
    def __init__(self, data):
        self.data = data
        parser = expat.ParserCreate()
        parser.StartElementHandler = self.startNode
        parser.EndElementHandler = self.endNode
        parser.CharacterDataHandler = self.dataNode
        self.stack = []
        self.routes = []
        self.host = {"name": None}
        parser.Parse(self.data)
        print("Traceroute from %s(%s) to %s(%s) for %s" % (self._from, self._sip, self._to, self._tip, self._srv))
        rid = 1
        for route in self.routes:
            if not "blocking" in route:
                print("Route %s: (%s)" % (rid, ",".join(route["reason"])))
                for host in route['hosts']:
                    hostdata = []
                    if "speculated" in  route['hosts'][host]:
                        hostdata.append("speculated")
                    if "blocking" in  route['hosts'][host]:
                        hostdata.append("blocking")
                    if "vr" in  route['hosts'][host] and route['hosts'][host]["vr"]:
                        hostdata.append("vr:"+ route['hosts'][host]["vr"])
                    if "viavr" in  route['hosts'][host] and route['hosts'][host]["viavr"]:
                        hostdata.append("viavr:"+ route['hosts'][host]["viavr"])
                    print(" * %s (%s)" % (host, ",".join(hostdata)))
                rid += 1
                print()
            else:
                logging.warning("Filtering blocking route")

    def startNode(self, name, attrs):
        self.stack.append(name)
        path = ".".join(self.stack)
        if (path == "Access-Route.route-holder.route-descriptions.route-description"):
            self.route = {"hosts": {}, "reason": [], "blocking": None}

    def endNode(self, name):
        path = ".".join(self.stack)
        if (path == "Access-Route.route-holder.route-descriptions.route-description"):
            self.routes.append(self.route)
        self.stack.remove(name)
        
    def dataNode(self, data):
        host = self.host["name"]
        path = ".".join(self.stack)
        if (path == "Access-Route.from"):
            self._from = data
        elif (path == "Access-Route.to"):
            self._to = data
        elif (path == "Access-Route.source.source-ip-ranges"):
            self._sip = data
        elif (path == "Access-Route.source.sending-to-ip-ranges"):
            self._tip = data
        elif (path == "Access-Route.source.sending-to-services"):
            self._srv = data
        elif (path == "Access-Route.route-holder.route-descriptions.route-description.broken-reasons.broken-reason"):
            self.route["reason"].append(data)
        elif (path == "Access-Route.route-holder.route-descriptions.route-description.hops.hop.host.name"):
            self.host = {"name": data, "vr": None, "viavr": None, "blocking": None, "speculated": None}
            self.route["hosts"][data] = self.host
        elif (path == "Access-Route.route-holder.route-descriptions.route-description.hops.hop.isSpeculated"):
            self.route["hosts"][host]["speculated"] = data
        elif (path == "Access-Route.route-holder.route-descriptions.route-description.hops.hop.isBlocking"):
            self.route["hosts"][host]["blocking"] = data
            self.route["blocking"] = True
        elif ("vr" in self.stack):
            self.route["hosts"][host]["vr"] = data
        elif ("viaVr" in self.stack):
            self.route["hosts"][host]["viavr"] = data

class loadCSV():
    
    def __init__(self, cfg):
        self.cfg = cfg
        
    def setColumns(self, cols, a, b):
        columns = []
        for c in cols:
            columns.append("%s.%s=%s.%s" % (a, c, b, c))
        return(",".join(columns))
        
    def tableColumns(self, cols, t=None):
        columns = []
        for c in cols:
            if t:
                columns.append("%s.%s" % (t, c))
            else:
                columns.append(c)
        return(",".join(columns))
    
    def loadTable(self, table, fle, model="live", lastmodcol="last_modification_time", columns=None, batch=10000):
        m = mysqlConnect('skyboxview_' + model, self.cfg)
        cursor = m.cursor()
        cursor.autocommit = None
        tmptable = table + "_tmp"
        if not columns:
            columns = []
            cursor.execute("SHOW columns FROM %s" % (table))
            for col in cursor.fetchall():
                columns.append(col[0])
        columns.remove('id')
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
        logging.warning("Loading table %s" % (tmptable))
        try:
            cursor.execute('DROP TABLE %s' % (tmptable))
        except mysql.connector.errors.ProgrammingError:
            pass
        cursor.execute('CREATE TABLE %s LIKE %s' % (tmptable, table))
        startdate = int(time.time())
        cursor.execute('LOAD DATA INFILE "%s" REPLACE INTO TABLE %s CHARACTER SET BINARY' % (fle, tmptable))
        logging.warning("Loaded %s rows" % (cursor.rowcount))
        
        logging.warning("Locking tables...")
        cursor.execute('LOCK TABLES %s AS F WRITE, %s AS T WRITE, %s WRITE, %s WRITE' % (tmptable, table, tmptable, table))
        cursor.execute('SET FOREIGN_KEY_CHECKS=0')
        cursor.execute('UPDATE %s AS T LEFT JOIN %s AS F ON (F.id=T.id) SET %s WHERE (F.id IS NOT NULL AND T.%s<F.%s)' % (table, tmptable, self.setColumns(columns, "T", "F"), lastmodcol, lastmodcol))
        logging.warning("Updated %s rows" % (cursor.rowcount))
        
        cursor.execute('DELETE T FROM %s AS T LEFT JOIN %s AS F on F.id = T.id WHERE (F.id Is NULL)' % (table, tmptable))
        logging.warning("Deleted %s rows" % (cursor.rowcount))
        
        cursor.execute('INSERT INTO %s (id,%s) SELECT F.id,%s FROM %s AS F LEFT JOIN %s AS T ON (T.id=F.id) WHERE T.id Is NULL' % (table, self.tableColumns(columns), self.tableColumns(columns, "F"), tmptable, table))
        logging.warning("Inserted %s rows" % (cursor.rowcount))
        
        logging.warning("Unlocking table %s" % (table))
        cursor.execute('UNLOCK TABLES')
        
        cursor.execute('SET FOREIGN_KEY_CHECKS=1')
        cursor.execute('DROP TABLE %s' % (tmptable))
        m.commit()
        logging.warning("Commiting table %s" % (table))

        
        
    

