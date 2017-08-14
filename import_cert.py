#!/usr/bin/python3
# Author: David Chidell (dchidell)

#################################
# This script will install SSL certificates into a Cisco IOS router for WEBVPN usage.
# This differs from ssl_cert.py in the sense that this simply loads existing certificates into the router. It does not attempt to get them from LetsEncrypt.
#################################
# The following configuration is performed as a result of this script:
# * Existing crypto components removed and cleaned
# * Private key re-generation to 3des format
# * Crypto components re-inserted with newly generated information
# * WEBVPN gateway updated and restarted
##################################
# Usage: 'python3 ssl_cert.py 10.75.23.1 CA_LETSENCRYPT vpn.example.com,example.com /var/www/html'
##################################
# Requirements:
# * Python libraries: netmiko, argparse, getpass
# * Cisco IOS router with WEBVPN configured
# * Access to certificate files
##################################

import argparse
import os.path
import subprocess

import netmiko


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch SSL certificates and install them into an IOS router for SSL WEBVPN automatically.")
    parser.add_argument("--u", metavar="admin", help="Username (will prompt via stdin if empty)")
    parser.add_argument("--p", metavar="mypassword", help="Password (will prompt via stdin if empty)")
    parser.add_argument("--renewtime", metavar="3024000", help="Renewal check time in seconds (default 35 days)", default="3024000")
    parser.add_argument("--sshkey", metavar="/path/to/ssh/key.rsa", help="Path to router public SSH key")
    parser.add_argument("--gateway", metavar="VPNGW",
                        help="Define VPN gateway on router - default attempts to find it out")
    parser.add_argument("--forcereplace", help="Forces the script to re-apply the cert to the router - expired or not.",
                        action="store_true")
    parser.add_argument("ip", help="IP / hostname")
    parser.add_argument("name", help="Cert / trustpoint name")
    parser.add_argument("cert_key", help="Private Key", default="privkey.pem")
    parser.add_argument("cert_primary", help="Primary Certificate", default="cert.pem")
    parser.add_argument("cert_ca", help="CA Certificate", default="chain.pem")
    return parser.parse_args()


def router_connect(ip, user, passw, key):
    if key is not None:
        router_info = {'device_type': 'cisco_ios', 'ip': ip, 'username': user, 'use_keys': True, 'key_file': key}
    else:
        router_info = {'device_type': 'cisco_ios', 'ip': ip, 'username': user, 'password': passw}

    try:
        term = netmiko.ConnectHandler(**router_info)
    except netmiko.ssh_exception.NetMikoAuthenticationException:
        print('Error: Unable to authenticate to router. Bad username or password')
        exit()
    except netmiko.ssh_exception.NetMikoTimeoutException:
        print('Error: Unable to connect to IP. Timed out.')
        exit()
    return term


def remove_key(term, key_name):
    if (term.send_command('show crypto key mypubkey rsa ' + key_name) == ''):
        return False
    else:
        term.send_config_set(['crypto key zeroize rsa ' + key_name, 'yes'])
        return True


def remove_cert(term, cert_name):
    if (term.send_command('show crypto pki certificates ' + cert_name) == ''):
        return False
    else:
        term.send_config_set(['no crypto pki certificate chain ' + cert_name, 'yes'])
        return True


def remove_tp(term, tp_name):
    if (term.send_command('show crypto pki trustpoint ' + tp_name) == ''):
        return False
    else:
        term.send_config_set(['no crypto pki trustpoint ' + tp_name, 'yes'])
        return True


def remove_crypto(term, name):
    if (remove_key(term, name)):
        print('Removed key ' + name)
    else:
        print('No key found, proceeding...')

    if (remove_cert(term, name)):
        print('Removed cert ' + name)
    else:
        print('No cert found, proceeding...')

    if (remove_tp(term, name)):
        print('Removed trustpoint ' + name)
    else:
        print('No trustpoint found, proceeding...')


def create_tp(term, name):
    term.send_config_set(['crypto pki trustpoint ' + name])
    term.send_config_set(['enrollment terminal pem'])


def cert_valid(cert_path,seconds):
    return not subprocess.call('openssl x509 -checkend {} -in {} > /dev/null'.format(seconds,cert_path), shell=True)


def are_certs_present(cert_key, cert_primary, cert_ca):
    if os.path.isfile(cert_primary):
        if os.path.isfile(cert_ca):
            if os.path.isfile(cert_key):
                return True
    return False


def import_cert(term, name, key_password, intermediate_cert, priv_key, ssl_cert):
    command_list = ['crypto pki import {} pem terminal password {}'.format(name, key_password)]
    cert_list = [intermediate_cert, priv_key, ssl_cert]
    for item in cert_list:
        with open(item, 'r') as fileh:
            command_list.append(fileh.read())
            command_list.append('quit')
    term.send_config_set(command_list)


def convert_key(key, password):
    return not subprocess.call(
        'openssl rsa -in {} -out {}.3des -des3 -passout pass:"{}" > /dev/null'.format(key, key, password), shell=True)


def configure_gateway(term, gateway, name):
    if (gateway is None):
        out = term.send_command('show webvpn gateway')
        if (out == ''):
            print('Error: Unable to find any webvpn gateways! Exiting.')
            exit()
        # This is ugly as hell, but seems to work!
        gateway = out.split('\n')[0].split(' ')[2]
    term.send_config_set(
        ['webvpn gateway ' + gateway, 'no inservice', 'no ssl trustpoint ' + name, 'ssl trustpoint ' + name,
         'inservice'])


def main():
    # Load arguments into local variables - bit messy but oh well
    args = parse_args()
    user = args.u
    passw = args.p
    tp_name = args.name
    keys = args.sshkey
    gateway = args.gateway
    ip = args.ip

    cert_pass = passw if passw is not None else 'KeyPassword'

    # Build certificate path strings
    intermediate_path = args.cert_ca
    key_path = args.cert_key
    cert_path = args.cert_primary

    # Check to see if our certificate has or will expire soon
    if (cert_valid(cert_path,args.renewtime)):
        print('Server certificate has not expired and will not expire in the renewtime. Use --forcereplace switch to force the cert to the router.')
        if (args.forcereplace):
            print('Forcing cert replacement enabled. Renewing...')
        else:
            exit()
    else:
        print('Cert has expired or is expiring soon! RENEW ASAP!!!!!')
        exit(1)

    # Check presence of certificates
    if are_certs_present(key_path, cert_path, intermediate_path):
        print('Found certificates!')
    else:
        print('Error: Unable to find certs! Check the following exist:')
        print(cert_path)
        print(intermediate_path)
        print(key_path)
        exit()

    # Convert private key to 3des format. We'll just use the SSH password for the key, why not
    if convert_key(key_path, cert_pass):
        print('Successfully converted RSA key to 3des format!')
    else:
        print('Error: OpenSSL encountered an error when running.')
        if os.path.isfile(key_path + '.3des'):
            print('Despite the error, we found a 3des key, attempting to use it!')
        else:
            print('There is no 3des key to use as a result of the failure. Exiting.')
            exit(1)

    # Connect to the router, error handling performed in the function
    print('Connecting to router...')
    session = router_connect(ip, user, passw, keys)

    # Remove the old crypto stuff (key, cert and trustpoint)
    print('Checking for and removing previous crypto objects...')
    remove_crypto(session, tp_name)

    # Create the new trustpoint
    print('Creating the new trustpoint...')
    create_tp(session, tp_name)

    # Here's the big one, import the new certs
    print('Importing certificate into router')
    import_cert(session, tp_name, cert_pass, intermediate_path, key_path + '.3des', cert_path)

    print('Configuring trustpoint on VPN gateway.')
    configure_gateway(session, gateway, tp_name)


main()
