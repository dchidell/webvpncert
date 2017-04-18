#!/usr/bin/python3
#Author: David Chidell (dchidell)

#################################
#This script will fetch and install SSL certificates into a Cisco IOS router for WEBVPN usage.
#################################
#The following configuration is performed as a result of this script:
# * Certificate generated (via LetsEncrypt)
# * Existing crypto components removed and cleaned
# * Private key re-generation to 3des format
# * Crypto components re-inserted with newly generated information
# * WEBVPN gateway updated and restarted
##################################
# Usage: 'python3 ssl_cert.py 10.75.23.1 CA_LETSENCRYPT vpn.example.com,example.com /var/www/html'
##################################
# 

import netmiko
import subprocess
import argparse
import getpass
import os.path

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch SSL certificates and install them into an IOS router for SSL WEBVPN automatically.")
    parser.add_argument("--u",metavar="admin", help="Username (will prompt via stdin if empty)")
    parser.add_argument("--p",metavar="mypassword",help="Password (will prompt via stdin if empty)")
    parser.add_argument("--acme",metavar="/root/.acme.sh", help="Acme script path - default /root/.acme.sh",default="/root/.acme.sh")
    parser.add_argument("--gateway",metavar="VPNGW",help="Define VPN gateway on router - default attempts to find it out")
    parser.add_argument("--noreplace",help="If the certificate is not expiring, this program will not attempt to replace it in the router",action="store_true")
    parser.add_argument("ip",help="IP / hostname")
    parser.add_argument("name",help="Cert / trustpoint name")
    parser.add_argument("domain",help="Domain: example.com or example.com,subdomain.example.com,test.example.com")
    parser.add_argument("webroot",help="Web root directory")
    return parser.parse_args()

def router_connect(ip,user,passw):
    router_info = {'device_type':'cisco_ios','ip':ip,'username':user,'password':passw}
    try:
        term = netmiko.ConnectHandler(**router_info)
    except netmiko.ssh_exception.NetMikoAuthenticationException:
        print('Error: Unable to authenticate to router. Bad username or password')
        exit()
    except netmiko.ssh_exception.NetMikoTimeoutException:
        print('Error: Unable to connect to IP. Timed out.')
        exit()
    return term

def remove_key(term,key_name):
    if(term.send_command('show crypto key mypubkey rsa '+key_name) == ''):
        return False
    else:
        term.send_config_set(['crypto key zeroize rsa '+key_name,'yes'])
        return True

def remove_cert(term,cert_name):
    if(term.send_command('show crypto pki certificates '+cert_name) == ''):
        return False
    else:
        term.send_config_set(['no crypto pki certificate chain '+cert_name,'yes'])
        return True

def remove_tp(term,tp_name):
    if(term.send_command('show crypto pki trustpoint '+tp_name) == ''):
        return False
    else:
        term.send_config_set(['no crypto pki trustpoint '+tp_name,'yes'])
        return True

def remove_crypto(term,name):
    if(remove_key(term,name)):
        print('Removed key '+name)
    else:
        print('No key found, proceeding...')

    if(remove_cert(term,name)):
        print('Removed cert '+name)
    else:
        print('No cert found, proceeding...')

    if(remove_tp(term,name)):
        print('Removed trustpoint '+name)
    else:
        print('No trustpoint found, proceeding...')

def create_tp(term,name):
    term.send_config_set(['crypto pki trustpoint '+name])
    term.send_config_set(['enrollment terminal pem'])

def cert_valid(cert_path):
    return not subprocess.call('openssl x509 -checkend 86400 -in {} > /dev/null'.format(cert_path),shell=True)

def renew_cert(domain_list,acme_path,webroot,show_error=False):
    domain_string = ''
    domain_list = sorted(domain_list,key=lambda domain: len(domain.split('.')))
    for domain in domain_list:
        domain_string += '-d '+domain+' '
    out = subprocess.Popen('{}/acme.sh --issue --force {}-w {}'.format(acme_path,domain_string,webroot),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    msg = out.communicate()
    code = out.returncode
    if code and show_error:
        print(msg[1])
    return code

def get_root_domain(domain_list):
    return sorted(domain_list,key=lambda domain: len(domain.split('.')))[0]

def are_certs_present(dir,root_domain):
    if(os.path.isfile(dir+'/'+root_domain+'/'+root_domain+'.cer')):
        if(os.path.isfile(dir+'/'+root_domain+'/'+'ca.cer')):
            if(os.path.isfile(dir+'/'+root_domain+'/'+root_domain+'.key')):
                return True
    return False

def import_cert(term,name,key_password,intermediate_cert,priv_key,ssl_cert):
    command_list = ['crypto pki import {} pem terminal password {}'.format(name,key_password)]
    cert_list = [intermediate_cert,priv_key,ssl_cert]
    for item in cert_list:
        with open(item,'r') as fileh:
            command_list.append(fileh.read())
            command_list.append('quit')
    term.send_config_set(command_list)

def convert_key(key,password):
    return not subprocess.call('openssl rsa -in {} -out {}.3des -des3 -passout pass:"{}" > /dev/null'.format(key,key,password),shell=True)

def configure_gateway(term,gateway,name):
    if(gateway is None):
        out = term.send_command('show webvpn gateway')
        if(out == ''):
            print('Error: Unable to find any webvpn gateways! Exiting.')
            exit()
        #This is ugly as hell, but seems to work!
        gateway = out.split('\n')[0].split(' ')[2]
    term.send_config_set(['webvpn gateway '+gateway,'no inservice','no ssl trustpoint '+name,'ssl trustpoint '+name,'inservice'])

def main():
    args = parse_args()
    user = input('Enter Username: ') if args.u is None else args.u
    passw = getpass.getpass('Enter Password: ') if args.p is None else args.p
    tp_name = args.name
    acme_path = '/root/.acme.sh' if args.acme is None else args.acme
    domains = args.domain.split(',')
    webroot = args.webroot
    gateway = args.gateway
    ip = args.ip
    renew_required = True

    #Check we have at least one valid domain in here
    if(len(args.domain.split('.')) < 2):
        print('Error: Domain must be a valid TLD: e.g. example.com or a comma seperated list example.com')
        exit()

    #Get the 'root' domain. Easiest way is by checking how many times we can split a domain about a full stop.
    root_domain = get_root_domain(domains)

    #Check the existence of the acme.sh shell script
    if(os.path.isfile(acme_path+'/acme.sh')):
        print('Path to acme.sh appears valid!')
    else:
        print('Error: Unable to find acme.sh in: '+acme_path)
        exit()

    #Build certificate path strings
    intermediate_path = '{}/{}/ca.cer'.format(acme_path,root_domain)
    key_path = '{}/{}/{}.key'.format(acme_path,root_domain,root_domain)
    cert_path = '{}/{}/{}.cer'.format(acme_path,root_domain,root_domain)

    #Check to see if our certificate has or will expire soon
    if(cert_valid(cert_path.format(acme_path,root_domain,root_domain))):
        print('Server certificate has not expired and will not expire in the next day. Not renewing with LetsEncrypt')
        if(args.noreplace == True):
            print('--noreplace argument detected. Certificate state is OK. Not proceeding further.')
            exit()
    else:
        print('Cert has expired or is expiring soon! Renewing...')
        if(renew_cert(domains,acme_path,webroot,show_error=True)):
            print('Error: Acme.sh encountered an error when running')

    #Check presence of certificates
    if(are_certs_present(acme_path,root_domain)):
        print('Found certificates!')
    else:
        print('Error: Unable to find certs in acme path. Check the following exist:')
        print(cert_path)
        print(intermediate_path)
        print(key_path)
        exit()

    #Convert private key to 3des format. We'll just use the SSH password for the key, why not
    if(convert_key(key_path,passw)):
        print('Successfully converted RSA key to 3des format!')
    else:
        print('Error: OpenSSL encountered an error when running.')
        if(os.path.isfile(key_path+'.3des')):
            print('Despite the error, we found a 3des key, attempting to use it!')
        else:
            print('There is no 3des key to use as a result of the failure. Exiting.')
            exit()

    #Connect to the router, error handling performed in the function
    print('Connecting to router...')
    session = router_connect(ip,user,passw)

    #Remove the old crypto stuff (key, cert and trustpoint)
    print('Checking for and removing previous crypto objects...')
    remove_crypto(session,tp_name)

    #Create the new trustpoint
    print('Creating the new trustpoint...')
    create_tp(session,tp_name)

    #Here's the big one, import the new certs
    print('Importing certificate into router')
    import_cert(session,tp_name,passw,intermediate_path,key_path+'.3des',cert_path)

    print('Configuring trustpoint on VPN gateway.')
    configure_gateway(session,gateway,tp_name)

main()
