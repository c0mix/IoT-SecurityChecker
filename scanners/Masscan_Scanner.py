import subprocess
import re
from pathlib import Path
import shutil
import logging
import datetime

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green

class Masscan(object):
    """
    Implements masscan object in order to perform an IoTs scan
    """

    def __init__(self, target, prefix, binary, max_rate, wait_time, outdir):
        self.binary = binary
        self.max_rate = max_rate
        self.wait_time = wait_time
        self.timeout = 60
        self.output_format = "grepable"
        self.user_agent = str("Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_(KHTML,_like_Gecko)_Chrome/"
                              "60.0.3112.90_Safari/537.36")
        self.outfile = ''
        self.prefix = prefix
        self.target = target
        self.outdir = outdir


    def get_outfile(self):
        return self.outfile


    def check_binary(self):
        """
        Check if the exectuble is ok and could be run
        :return: boolean
        """
        if shutil.which(self.binary):
            return True
        else:
            logging.warning(R+'The supplied binary or path does not exist... Exiting'+W)
            exit(1)


    def cleanup(self):
        try:
            cmd = ["iptables","--check","INPUT", "-p", "tcp", "--dport", "60000", "-j", "DROP"]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            out, err = p.communicate()
            if err.decode('utf-8') == '':
                cmd = ["iptables","-D","INPUT", "-p", "tcp", "--dport", "60000", "-j", "DROP"]
                check_system_proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
                check_system_proc.wait()
        except Exception as e:
            logging.warning(R+'Error in cleanup: '+str(e)+W)


    def check_system(self):
        try:
            cmd = ["iptables","--check","INPUT", "-p", "tcp", "--dport", "60000", "-j", "DROP"]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            out, err = p.communicate()
            if 'Bad rule' in str(err):
                cmd = 'iptables -A INPUT -p tcp --dport 60000 -j DROP'
                check_system_proc = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
                check_system_proc.wait()
        except Exception as e:
            logging.warning(R+'Error in check_system: '+str(e)+W)


    def check_target_file(self):
        """
        check if target is a file or a single ip, than modify masscan's command line with -iL
        :return: true if is file, false if is IP
        """
        if re.match('^\d+\.\d+\.\d+\.\d+$', self.target) or re.match('^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$', self.target) or \
                re.match('^\d+\.\d+\.\d+\.\d+/\d+$', self.target):
            return False
        elif Path(self.target).is_file():
            return True
        else:
            logging.warning(R+'The supplied targets list does not exist... Exiting'+W)
            exit(1)


    def run(self):
        """
        Let start the scan!
        :return:
        """
        self.outfile = str(self.prefix) + str(self.target).replace("/", "_").replace('.', '-') + \
                       'T{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())+".txt"
        out = self.outdir + self.outfile

        params = {
            "binary" : self.binary,
            "max-rate": self.max_rate,
            "wait-time": self.wait_time,
            "timeout": self.timeout,
            "output-format": self.output_format,
            "user-agent": self.user_agent,
            "outfile": out,
            "target": self.target
        }

        if self.check_target_file():
            cmd = "%(binary)s --banners --max-rate %(max-rate)s --nocapture cert --wait %(wait-time)s --connection-timeout %(timeout)s  --source-port 60000 " \
                  "--output-format %(output-format)s -p 47808,20000,44818,1911,4911,2404,789,502,102,10000,1080,11,137,143,1883,1900,21,22,23,25," \
                  "37777,443,4433,4443,445,4567,49152,5222,5431,554,5683,631,7547,80,8000,8023,8080,8081,8088,81,82,83,84,8443," \
                  "88,8883,8888,9000,9090,9999 --open --output-file %(outfile)s -iL %(target)s --http-user-agent %(user-agent)s" % params

        else:
            cmd = "%(binary)s --banners --max-rate %(max-rate)s --nocapture cert --wait %(wait-time)s --connection-timeout %(timeout)s --source-port 60000 " \
                  "--output-format %(output-format)s -p 47808,20000,44818,1911,4911,2404,789,502,102,10000,1080,11,137,143,1883,1900,21,22,23,25," \
                  "37777,443,4433,4443,445,4567,49152,5222,5431,554,5683,631,7547,80,8000,8023,8080,8081,8088,81,82,83,84,8443," \
                  "88,8883,8888,9000,9090,9999 --open --output-file %(outfile)s %(target)s --http-user-agent %(user-agent)s" % params

        try:
            logging.info('Starting scan process...')
            logging.debug('Masscan command: '+cmd)
            masscanproc = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
            masscanproc.wait()
            logging.info(G+'Scan process completed!'+W)
        except Exception as e:
            logging.warning(R+'Process error... %s Exiting' % str(e)+W)