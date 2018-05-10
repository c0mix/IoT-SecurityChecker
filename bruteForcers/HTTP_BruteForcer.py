# Original tool from https://github.com/erforschr/http-auth-bruteforcer

import requests
import requests_ntlm
import grequests
import validators
import datetime
import time
import logging


# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green


class ContinueBrute(Exception):
    pass


class HTTPAuthUtils:
    @staticmethod
    def get_credentials_from_basic_requests(reqs_list):
        credentials_list = []

        for req in reqs_list:
            req_resp_status_code = vars(vars(req)['response'])['status_code']

            if req_resp_status_code == 200:
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']
                credentials_list.append(Credentials(req_username, req_password))

        return credentials_list

    @staticmethod
    def get_credentials_from_digest_requests(reqs_list):
        credentials_list = []

        for req in reqs_list:
            req_resp_status_code = vars(vars(req)['response'])['status_code']

            if req_resp_status_code == 200:
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']
                credentials_list.append(Credentials(req_username, req_password))

        return credentials_list

    @staticmethod
    def get_credentials_from_ntlm_requests(reqs_list):
        credentials_list = []

        for req in reqs_list:
            req_resp_status_code = vars(vars(req)['response'])['status_code']

            if req_resp_status_code == 200:
                req_domain = vars(vars(req)['kwargs']['auth'])['domain']
                req_username = vars(vars(req)['kwargs']['auth'])['username']
                req_password = vars(vars(req)['kwargs']['auth'])['password']
                credentials_list.append(Credentials(req_domain + '\\' + req_username, req_password))

        return credentials_list


class Credentials:
    def __init__(self, username, password):
        self.username = username
        self.password = password


class HTTP_BruteForcer():
    def __init__(self, target_list, authtype, credfile):
        self.authtype = self.check_arg_auth_type(authtype)
        self.credfile = open(credfile,'r')
        self.target_list = target_list
        self.findings = []


    def check_arg_url(self, value):
        try:
            validators.url(value)
        except Exception:
            logging.warning(R+'URL is not valid'+W)
            return False
        return True


    def check_arg_auth_type(self, value):
        if value not in ['basic', 'digest', 'ntlm']:
            raise Exception('Authentication type not valid')
        return value


    def credentials_generator_from_credentials_file(self, credentials_file_object, buffer_size):
        credentials_buffer = []
        credentials_file_object.seek(0)
        for line in credentials_file_object:
            username = line.strip().split(':')[0]
            password = line.strip().split(':')[1]

            credentials = Credentials(username, password)

            credentials_buffer.append(credentials)

            if len(credentials_buffer) >= buffer_size:
                yield credentials_buffer
                credentials_buffer = []

        if len(credentials_buffer) != 0:
            yield credentials_buffer


    def test_basic_auth(self, url, credentials_buffer):
        auth_successes = []

        timeout = 5
        verify = False

        requests_buffer = []

        for credentials in credentials_buffer:
            try:
                auth = requests.auth.HTTPBasicAuth(credentials.username, credentials.password)
                requests_buffer.append(grequests.get(url=url, auth=auth, verify=verify, timeout=timeout))
            except Exception:
                pass
        resps = grequests.map(requests_buffer)

        try:
            if 200 in [resp.status_code for resp in resps]:
                    credentials = HTTPAuthUtils.get_credentials_from_basic_requests(requests_buffer)
                    auth_successes.extend(credentials)
        except Exception:
            pass
        return auth_successes


    def test_digest_auth(self, url, credentials_buffer):
        auth_successes = []

        timeout = 5
        verify = False

        requests_buffer = []

        for credentials in credentials_buffer:
            try:
                auth = requests.auth.HTTPDigestAuth(credentials.username, credentials.password)
                requests_buffer.append(grequests.get(url=url, auth=auth, verify=verify, timeout=timeout))
            except Exception:
                pass
        resps = grequests.map(requests_buffer)

        try:
            if 200 in [resp.status_code for resp in resps]:
                    credentials = HTTPAuthUtils.get_credentials_from_digest_requests(requests_buffer)
                    auth_successes.extend(credentials)
        except Exception:
            pass

        return auth_successes


    def test_ntlm_auth(self, url, credentials_buffer):
        auth_successes = []

        timeout = 15
        verify = False
        requests_buffer = []
        for credentials in credentials_buffer:
            auth = requests_ntlm.HttpNtlmAuth(credentials.username, credentials.password)
            requests_buffer.append(grequests.get(url=url, auth=auth, verify=verify, timeout=timeout))

        resps = grequests.map(requests_buffer)

        try:
            if 200 in [resp.status_code for resp in resps]:
                    credentials_list = HTTPAuthUtils.get_credentials_from_ntlm_requests(requests_buffer)
                    auth_successes.extend(credentials_list)
        except Exception:
            pass

        return auth_successes


    def check_url_requires_auth(self, url):
        try:
            resp = requests.get(url, verify=False, timeout=5)
        except Exception as e:
            logging.debug(R + 'Error %s while requesting URL + "' % str(e) + url + '"' + W)
            return False
        if resp.status_code != 401:
            return False

        return True


    def run(self):
        for target in self.target_list:
            creds_generator = []
            creds_generator = self.credentials_generator_from_credentials_file(credentials_file_object=self.credfile,
                                                                               buffer_size=10)
            count = 0
            print_count = 0
            host = target.split(':')[0]
            port = target.split(':')[1]
            logging.info('Testing: %s:%s' % (host, port))
            if port == 443:
                url = 'https://%s:%s/'% (host, str(port))
            else:
                url = 'http://%s:%s/'% (host, str(port))

            try:
                if not self.check_arg_url(url):
                    logging.warning(R+'Bad url, skip to next host'+W)
                    raise ContinueBrute

                url_requires_auth = self.check_url_requires_auth(url)
                if not url_requires_auth:
                    logging.warning(R+'Url does not requires auth, skip to next host'+W)
                    raise ContinueBrute

                logging.debug('Authentication tests begin...')
                logging.debug('Date: ' + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y'))

                for credentials_buffer in creds_generator:
                    auth_successes = []
                    if self.authtype == 'basic':
                        auth_successes = self.test_basic_auth(url, credentials_buffer)
                    elif self.authtype == 'digest':
                        auth_successes = self.test_digest_auth(url, credentials_buffer)
                    elif self.authtype == 'ntlm':
                        auth_successes = self.test_ntlm_auth(url, credentials_buffer)
                    else:
                        raise Exception('Auth type ' + self.authtype + ' not known')

                    if len(auth_successes) != 0:
                        for credentials in auth_successes:
                            logging.info(G+'Authentication success: username: ' + credentials.username +
                                         ', password: ' + credentials.password +W)
                            finding = host + ';' + port + ';' + 'HTTP' + ';' + 'Default Credentials' + ';' + 'HTTPBrute' + ';' + 'Authentication success: username: ' + credentials.username + ', password: ' + credentials.password
                            self.findings.append(finding)

                    count += len(credentials_buffer)

                    logging.debug('Authentication attempts: ' + str(count))

                    time.sleep(0.5)

                logging.debug('Date: ' + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y'))

            except ContinueBrute:
                continue

        return self.findings
