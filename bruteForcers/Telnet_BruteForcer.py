import telnetlib
import time
import logging
from threading import *

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green


# global variable for threads coordination
Found = False


class ContinueBrute(Exception):
    pass


class Telnet_BruteForcer(object):

    def __init__(self, target_list, credfile, thread):
        self.connection_lock = BoundedSemaphore(value=thread)
        self.findings = []
        self.target_list = target_list

        try:
            self.credfile = open(credfile,'r')
        except FileExistsError:
            logging.warning(R+'Credentials file does not exist, exiting...'+W)
            exit(1)


    def read_banner(self, telnet):
        """
        Read the telnet banner
        :param telnet: TelnetOBJ
        :return: string
        """
        banner = ''
        # Read telnet banner
        for i in range(0, 5):
            banner += str(telnet.read_very_eager())
            time.sleep(0.2)
        logging.debug('Banner: '+banner)


        # Need a new line char to print telnet prompt login
        if str(banner).replace("b''b''b'","").replace("'b''b''","") == '':
            # Send new line
            telnet.write(('').encode('ascii'))

            # Get telnet banner
            for i in range(0, 10):
              banner += str(telnet.read_very_eager())
              time.sleep(0.2)

        return banner


    def detect_loginType(self, banner):
        """
        Try to detect which is the type of telnet prompt
        :param banner: String
        :return: String
        """
        keywords_USPASS = ['login', 'Login', 'auth', 'user', 'username', 'Username', 'Account', 'asswor', 'id:', 'Login:']
        keywords_PASS = ['Password', 'password', 'pass', 'credential', 'Access Verification']
        keywords_INT = ['Press any key to continue', 'Press RETURN to activate console', 'press']
        type = 'None'

        if any(word in banner for word in keywords_USPASS):
            type = 'UP'

        elif any(word in banner for word in keywords_PASS):
            type = 'P'

        elif any(word in banner for word in keywords_INT):
            type = 'I'

        return type


    def auth_success(self, banner):
        """
        Parse the telnet response for id command an try to determinate if the authentication succeeded
        :param banner:
        :return:
        """
        keywords_ID = [
            'uid=',
            '#',
            'invalid',
            'Invalid',
            'id',
            'Id',
            'unknown',
            'command',
            'is not recognized as an internal or external command',
            'riconosciuto come comando interno o esterno',
            'Invalid command',
            'id: not set',
            'id: command not found',
            '"id" is not a valid selection',
            'Unrecognized command',
            'Unknown command',
            'Available commands:',
            'Valid commands are',
            'unknown keyword id'
        ]

        if any(word in banner for word in keywords_ID):
            return True
        else:
            return False


    def connect(self, host, user, password, port, release):
        """
        handle the telnet connection and try the credentials
        :param host: string
        :param user: string
        :param password: string
        :param port: int
        :param release: boolean
        :return:
        """
        global Found

        try:
            tel = telnetlib.Telnet(host=host, port=int(port), timeout=3)
            banner = self.read_banner(tel)
            banner_type = self.detect_loginType(banner)
            if banner_type == 'UP':
                tel.write((user + '\r\n').encode('ascii'))
                time.sleep(1)
                tel.write((password + '\r\n').encode('ascii'))
                time.sleep(1)
                tel.write(('id\r\n').encode('ascii'))
                if self.auth_success(self.read_banner(tel)):
                    logging.info( G+ 'Telnet Password Found for host: %s:%s \nUsername: %s \nPassword: %s' % (
                        host, port, user, password) +W)
                    finding = host + ';' + port + ';' + 'Telnet' + ';' + 'Default Credentials' + ';' + 'TelnetBrute' + \
                              ';' + 'Telnet Password Found for host: %s:%s Username: %s Password: %s' % (
                        host, port, user, password)
                    self.findings.append(finding)
                    Found = True

            elif banner_type == 'P':
                tel.write((password + '\r\n').encode('ascii'))
                time.sleep(1)
                tel.write(('id\r\n').encode('ascii'))
                if self.auth_success(self.read_banner(tel)):
                    logging.info(G + 'Telnet Password Found for host: %s:%s \nUsername: %s \nPassword: %s' % (
                        host, port, user, password)+W)
                    finding = host + ';' + port + ';' + 'Telnet' + ';' + 'Default Credentials' + ';' + 'TelnetBrute' + \
                              ';' + 'Telnet Password Found for host: %s:%s Username: %s Password: %s' % (
                        host, port, user, password)
                    self.findings.append(finding)
                    Found = True

            elif banner_type == 'I':
                tel.write(('\r\n').encode('ascii'))
                time.sleep(0.5)
                tel.write((user + '\r\n').encode('ascii'))
                time.sleep(1)
                tel.write((password + '\r\n').encode('ascii'))
                time.sleep(1)
                tel.write(('id\r\n').encode('ascii'))
                if self.auth_success(self.read_banner(tel)):
                    logging.info(G+ 'Telnet Password Found for host: %s:%s \nUsername: %s \nPassword: %s' % (
                        host, port, user, password)+W)
                    finding = host + ';' + port + ';' + 'Telnet' + ';' + 'Default Credentials' + ';' + 'TelnetBrute' + \
                              ';' + 'Telnet Password Found for host: %s:%s Username: %s Password: %s' % (
                        host, port, user, password)
                    self.findings.append(finding)
                    Found = True

            else:
                logging.debug(R+'No banner type detected, trying generic brute force'+W)

            tel.close()
        except Exception as e:
            logging.warning(R+'Error: '+str(e)+W)

        finally:
            if release:
                pass

    def run(self):
        """
        launch the attack
        :return:
        """
        global Found

        for host in self.target_list:
            target = host.split(':')[0]
            port = host.split(':')[1]
            self.credfile.seek(0)
            try:
                for line in self.credfile.readlines():
                    if Found:
                        time.sleep(1)
                        raise ContinueBrute
                    user = line.split(':')[0]
                    password = line.split(':')[1].strip('\r').strip('\n')
                    logging.debug('Testing host: %s:%s \nUsername: %s \nPassword: %s' % (target, port, user, password))
                    self.connect(target, user, password, port, True)
            except ContinueBrute:
                Found = False
                continue

        time.sleep(1)
        return self.findings


