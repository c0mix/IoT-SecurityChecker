import ast

from Utils import *
from bruteForcers import SSH_BruteForcer, FTP_BruteForcer, Telnet_BruteForcer, HTTP_BruteForcer
from databases import DataBase_Class
from exploits import h264_dvr_rce, rom_0, Cisco_PVC_2300, Humax_HG100R, dlink, tv_ip410wn
from parsers import Masscan_Parser_Class
from scanners import Masscan_Scanner

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green
O = '\033[33m' # orange

# TODO shodan or zoomeye or censys integration + relative parsers

def iot_guess(portlist, hostlist):
    """
    Try to guess if a device is an IoT or not, please review the iotDetectionKeyword.txt file
    :param portlist: list
    :param hostlist: list
    :return:
    """
    iot = []
    db = open('resources/iotDetectionKeyword.txt','r')
    ##template:{'category':<cat-name>,'keywords':[list-of-key],'ports':[list-of-port],'manufacturers':[list-of-manufacturers],'vulns':[list-of-known-vulns]}

    # for each category of IoT defined inside the iotDetection.txt file perform an IoT identification
    # TODO refactoring -> too much for loops!
    for cat in db.readlines():
        logging.debug('Cat: '+cat)
        my_dict = {}
        try:
            my_dict = ast.literal_eval(cat)
        except:
            logging.warning(R+'Error during the eval evaluation of the dict'+W)
            logging.debug(R +'Log error line: ' + cat+W)

        #IoT detection based on open ports
        for device in portlist:
            logging.debug('DeviceA: ' + str(device))
            for port in device['ports']:
                logging.debug('Port: ' + port)
                if port in my_dict['ports']:
                    iot.append('Device: %s has Port %s open, compatible with %s' %
                                 (device['ip'], str(port), my_dict['category']))
                    logging.debug(G+'Device: %s has Port %s open, compatible with %s' %
                                 (device['ip'], str(port), my_dict['category'])+W)

        # IoT detection based on keywords in banner
        for device in hostlist:
            logging.debug('DeviceB: ' + str(device))
            for service in device['services']:
                logging.debug('Service: ' + service)
                for keyword in my_dict['keywords']:
                    logging.debug('Keyword: ' + keyword)
                    banner = service.split('/')
                    if (keyword.upper() in str(banner[1:]) or keyword.lower() in str(banner[1:])
                        or keyword in str(banner[1:])) and keyword != '':
                        iot.append('Device: %s has keyword: %s in port %s banner: %s' %
                                     (device['ip'], str(keyword), service.split('/')[0], str(banner[1:])))
                        logging.debug(G+'Device: %s has keyword: %s in port %s banner: %s' %
                                     (device['ip'], str(keyword), service.split('/')[0], str(banner[1:]))+W)
    return iot


if __name__=='__main__':
    finding_list = []
    iot_list = []
    args = arg_parsing()
    print_banner()
    check_root()
    scanner = Masscan_Scanner.Masscan(target=args.target,
                                      prefix=args.prefix,
                                      binary=args.binary,
                                      max_rate=args.max_rate,
                                      outdir=args.out_dir,
                                      wait_time=args.wait_time)
    scanner.check_binary()
    scanner.check_system()
    scanner.run()
    scanner.cleanup()
    parser = Masscan_Parser_Class.Masscan_Parser(file=args.out_dir+scanner.get_outfile())
    parsed_list = parser.parse()
    logging.info('Inserting data into scan DB...')
    back_to_user()
    db = DataBase_Class.Database()
    tab_name = scanner.get_outfile().strip('.txt').replace('-','_')
    db.create_scan_table(tab_name)
    db.insert_data(tab_name, parsed_list)
    rows = db.extract_dist_ip(tab_name)
    db.print_db_results(rows)
    device_service_list, device_port_list = db.exctract_port_ip(tab_name, rows)
    db.close_db()
    iot_list = iot_guess(device_port_list, device_service_list)
    for iot in sorted(list(set(iot_list))):
        logging.info(G+iot+W)

    # Bruteforce Checks
    if check_test_args(args.bruteforce, 'telnet'):
        db = DataBase_Class.Database()
        rows = db.extract_Telnet_ip(tab_name)
        telnet_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(telnet_list)>0:
            logging.info(O+'Starting Telnet brute forcing'+W)
            telnetBrute = Telnet_BruteForcer.Telnet_BruteForcer(target_list=telnet_list,
                                                                credfile='resources/wordlists/Telnet_credentials.txt',
                                                                thread=args.threads)
            findings = telnetBrute.run()

            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
            logging.debug(O+'Telnet brute forcing ended'+W)
        else:
            logging.warning(R+'No suitable hosts found for Telnet Bruteforce'+W)

    if check_test_args(args.bruteforce, 'ssh'):
        db = DataBase_Class.Database()
        rows = db.extract_SSH_ip(tab_name)
        ssh_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(ssh_list)>0:
            logging.info(O+'Starting SSH brute forcing'+W)
            sshBrute = SSH_BruteForcer.SSH_BruteForcer(target_list=ssh_list,
                                                       credfile='resources/wordlists/SSH_credentials.txt',
                                                       thread=args.threads)
            findings = sshBrute.run()
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
            logging.debug(O+'SSH brute forcing ended'+W)
        else:
            logging.warning(R+'No suitable hosts found for SSH Bruteforce'+W)

    if check_test_args(args.bruteforce, 'ftp'):
        db = DataBase_Class.Database()
        rows = db.extract_FTP_ip(tab_name)
        ftp_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(ftp_list)>0:
            logging.info(O+'Starting FTP brute forcing'+W)
            ftpBrute = FTP_BruteForcer.FTP_BruteForcer(target_list=ftp_list,
                                                       credfile='resources/wordlists/FTP_credentials.txt',
                                                       thread=args.threads)
            findings = ftpBrute.run()
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
            logging.debug(O+'FTP brute forcing ended'+W)
        else:
            logging.warning(R + 'No suitable hosts found for FTP Bruteforce' + W)

    if check_test_args(args.bruteforce, 'http'):
        db = DataBase_Class.Database()
        rows = db.extract_HTTP_ip(tab_name)
        http_list = list(set(db.create_list(rows)))
        db.close_db()
        authtype_list = ['basic', 'digest', 'ntlm']
        if len(http_list)>0:
            for authtype in authtype_list:
                logging.info(O+'Starting HTTP brute forcing with %s authtype'%authtype +W)
                httpBrute = HTTP_BruteForcer.HTTP_BruteForcer(target_list=http_list,
                                                          authtype=authtype,
                                                          credfile='resources/wordlists/HTTP_credentials.txt')
                findings = httpBrute.run()
                if len(findings) > 0:
                    for i in findings:
                        finding_list.append(i)
            logging.debug(O+'HTTP brute forcing ended'+W)
        else:
            logging.warning(R + 'No suitable hosts found for HTTP Bruteforce' + W)


    # Exploit Checks
    if check_test_args(args.exploits, 'DVR'):
        db = DataBase_Class.Database()
        rows = db.extract_DVR_ip(tab_name)
        dvr_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(dvr_list)>0:
            logging.info(O+'Starting h246-DVR-RCE exploit tests'+W)
            exploit = h264_dvr_rce.H264_dvr_rce(target_list=dvr_list)
            findings = exploit.exploit()
            logging.debug(O+'h246-DVR-RCE exploits tests ended'+W)
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
        else:
            logging.warning(R + 'No suitable hosts found for h246-DVR-RCE exploit test' + W)

    if check_test_args(args.exploits, 'ROM0'):
        db = DataBase_Class.Database()
        rows = db.extract_ROM_ip(tab_name)
        rom_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(rom_list)>0:
            logging.info(O+'Starting Rom-0 exploit tests'+W)
            exploit = rom_0.Rom_0(target_list=rom_list)
            findings = exploit.run()
            logging.debug(O+'Rom-0 exploits tests ended'+W)
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
        else:
            logging.warning(R + 'No suitable hosts found for Rom-0 exploit test' + W)


    if check_test_args(args.exploits, 'CISCOPVC'):
        db = DataBase_Class.Database()
        rows = db.extract_cisco_pvc_ip(tab_name)
        cisco_pvc_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(cisco_pvc_list)>0:
            logging.info(O+'Starting Cisco-PVC-2300 exploit tests'+W)
            exploit = Cisco_PVC_2300.Cisco_PVC(target_list=cisco_pvc_list)
            findings = exploit.run()
            logging.debug(O+'Cisco-PVC-2300 exploit tests ended'+W)
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
        else:
            logging.warning(R + 'No suitable hosts found for Cisco-PVC-2300 exploits test' + W)



    if check_test_args(args.exploits, 'DLINK'):
        db = DataBase_Class.Database()
        rows = db.extract_dlink_ip(tab_name)
        dlink_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(dlink_list)>0:
            logging.info(O+'Starting D-Link exploits tests'+W)
            exploit = dlink.Dlink_multiple(target_list=dlink_list)
            findings = exploit.run()
            logging.debug(O+'D-Link exploits tests ended'+W)
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
        else:
            logging.warning(R + 'No suitable hosts found for D-Link exploits test' + W)


    if check_test_args(args.exploits, 'IPTV'):
        db = DataBase_Class.Database()
        rows = db.extract_tv_ip_ip(tab_name)
        tv_ip_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(tv_ip_list)>0:
            logging.info(O+'Starting Tv-ip 410WN exploit tests'+W)
            exploit = tv_ip410wn.IP_TV(target_list=tv_ip_list)
            findings = exploit.run()
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
            logging.debug(O+'Tv-ip 410WN exploit tests ended'+W)
        else:
            logging.warning(R + 'No suitable hosts found for Tv-ip 410WN exploits test' + W)

    if check_test_args(args.exploits, 'HUMAX'):
        db = DataBase_Class.Database()
        rows = db.extract_humax_ip(tab_name)
        humax_ip_list = list(set(db.create_list(rows)))
        db.close_db()
        if len(humax_ip_list)>0:
            logging.info(O+'Starting Humax exploit tests'+W)
            exploit = Humax_HG100R.Humax(target_list=humax_ip_list)
            findings = exploit.run()
            if len(findings) > 0:
                for i in findings:
                    finding_list.append(i)
            logging.debug(O+'Humax exploit tests ended'+W)
        else:
            logging.warning(R + 'No suitable hosts found for Humax exploits test' + W)


    logging.info('All tests executed! Generating report: %s' % (str(args.report_output)))
    if len(finding_list) > 0:
        make_report(finding_list, args.report_output)
