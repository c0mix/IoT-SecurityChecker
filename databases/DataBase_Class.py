import sqlite3
import logging


# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green
O = '\033[33m' # orange
B = '\033[34m' # blue
P = '\033[35m' # purple
C = '\033[36m' # cyan
T = '\033[93m' # tan
ast = '['+B+'*'+W+'] '
min = '['+R+'-'+W+'] '
plu = '['+G+'+'+W+'] '


class Database(object):

    def __init__(self):
        try:
            self.connection = sqlite3.connect('ScanDB.sqlite')
            self.cursor = self.connection.cursor()
        except:
            logging.warning(R+'Error while connecting to DB, exiting...'+W)
            exit(1)


    def close_db(self):
        self.cursor.close()
        self.connection.close()


    def execute_db(self, sql):
        self.cursor.execute(sql)
        self.connection.commit()


    def drop_table(self, tab_name):
        sql = 'drop table if exists %s' % tab_name
        self.cursor.execute(sql)


    def create_scan_table(self, tab_name):
        try:
            sql = 'create table %s (id int, Timestamp, IP, Port, Service, Banner, Info, Error, primary key(id))' % tab_name
            self.cursor.execute(sql)
            self.connection.commit()
            logging.info(G+'Table %s created successfully' % tab_name +W)
        except Exception as e:
            logging.warning(R+str(e)+W)
            logging.warning(R+'Error in table creation'+W)


    def insert_data(self, tab_name, parsed_data):
        try:
            sql = 'INSERT into %s (id, Timestamp, IP, Port, Service, Banner, Info, Error) values(?,?,?,?,?,?,?,?)' % tab_name
            self.cursor.executemany(sql, parsed_data)
            self.connection.commit()
            logging.debug('Records created successfully')
        except:
            logging.warning(R+'Error in data insert'+W)


    def print_db_results(self, rows):
        logging.info('List of all records found:')
        counter = 0
        for row in rows:
            counter += 1
            for key in row.keys():
                print('%s = %s' % (key, row[key]))
        logging.info('Total result: '+str(counter))


    def create_list(self, rows):
        list = []
        count = 0
        for row in rows:
            count +=1
            string = row[0]+':'+str(row[1])
            logging.debug("Line to insert: "+ string)
            list.append(string)
        logging.debug('Total line:'+str(count))
        return list


    def exctract_port_ip(self, tab_name, rows):
        """
        For each IP, extract ports and port:banner so you can have a list of IP:[ports] and a list of IP:[ports:banner]
        :param tab_name: string
        :param rows: tuple list
        :return: list, list
        """
        # TODO handle eventual encoding problems with banners!
        dev_list = []
        dev_port_list = []
        for row in rows:
            device = {
                'ip': '',
                'services': []
                }
            devicePort = {
                'ip': '',
                'ports': []
                }

            ip = row[row.keys()[0]]
            device['ip'] = ip
            devicePort['ip'] = ip
            logging.debug('IP: '+ip)
            sql = 'SELECT Port,Banner,Info FROM %s WHERE IP="%s"' %(tab_name, ip)
            self.cursor.execute(sql)
            self.cursor.row_factory = sqlite3.Row
            query_res = self.cursor.fetchall()
            logging.debug('qres: '+str(query_res))

            for row2 in query_res:
                logging.debug('row2: '+str(row2))
                port = row2[row2.keys()[0]]
                banner = row2[row2.keys()[1]]
                logging.debug('banner1: ' + banner)
                if banner == ' ':
                    # If banner is empty, try to insert "Info" field
                    banner = row2[row2.keys()[2]]
                    logging.debug('banner2: '+banner)

                string = str(port)+'/'+str(banner)
                logging.debug('string= '+string)
                devicePort['ports'].append(port)
                device['services'].append(string)

            dev_list.append(device)
            dev_port_list.append(devicePort)

        for dev in dev_port_list:
            logging.debug(dev['ports'])
            dev['ports'] = list(set(dev['ports']))

        logging.debug('dev_list: '+ str(dev_list))
        logging.debug('dev_port_list: ' + str(dev_port_list))

        return dev_list, dev_port_list


    def extract_all_data(self, tab_name):
        sql = 'SELECT * FROM %s' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_dist_ip(self, tab_name):
        sql = 'SELECT distinct IP,Port FROM %s' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_HTTP_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "80" OR Port = "443" OR Port = "8080" OR Service like "http" OR Info like "http"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_FTP_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "21" OR Port = "2121" OR Banner like "ftp" OR Service like "ftp" ' \
              'OR Info like "ftp"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_Telnet_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "23" OR Port = "2323" OR Banner like "telnet" OR ' \
              'Service like "telnet" OR Info like "telnet"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_SSH_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "22" OR Port = "2222" OR Banner like "ssh" OR Service like "ssh" OR ' \
              'Info like "ssh"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_DVR_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "80" OR Port = "443" OR Banner like "dvr" OR Service like "http" ' \
              'OR Info like "http"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_ROM_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "80" OR Port = "443" OR Banner like "dlink" OR Service like "http" ' \
              'OR Info like "http"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_cisco_pvc_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "81" OR Port = "80" OR Port = 8081 OR Banner like "lighttpd/1.4.13" ' \
              'OR Banner like "ip camera"' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_dlink_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "81" OR Port = "80" OR Port = "8081" OR Port = "8080" OR Banner like "dcs-lig-httpd" ' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_tv_ip_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "81" OR Port = "80" OR Port = "8081" OR Banner like "netcam" ' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()


    def extract_humax_ip(self, tab_name):
        sql = 'SELECT IP, Port FROM %s WHERE Port = "81" OR Port = "80" OR Port = "8081" OR Banner like "HUMAX Co." ' % tab_name
        self.cursor.execute(sql)
        self.cursor.row_factory = sqlite3.Row
        return self.cursor.fetchall()