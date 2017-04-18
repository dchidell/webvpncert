# webvpncert
Python script to import SSL certificates into IOS routers for WEBVPN

```
usage: ssl_cert.py [-h] [--u admin] [--p mypassword] [--acme /root/.acme.sh]
                   [--gateway VPNGW] [--noreplace]
                   ip name domain webroot

Fetch SSL certificates and install them into an IOS router for SSL WEBVPN
automatically.

positional arguments:
  ip                    IP / hostname
  name                  Cert / trustpoint name
  domain                Domain: example.com or
                        example.com,subdomain.example.com,test.example.com
  webroot               Web root directory

optional arguments:
  -h, --help            show this help message and exit
  --u admin             Username (will prompt via stdin if empty)
  --p mypassword        Password (will prompt via stdin if empty)
  --acme /root/.acme.sh
                        Acme script path - default /root/.acme.sh
  --gateway VPNGW       Define VPN gateway on router - default attempts to
                        find it out
  --noreplace           If the certificate is not expiring, this program will
                        not attempt to replace it in the router
root@dchidell-ubuntu:/home/david# 
```


Example:

python3 ssl_cert.py 10.75.23.1 CA_LETSENCRYPT vpn.example.com,example.com /var/www/html

This will prompt for SSH credentials for the router at 10.75.23.1 and attempt to generate a valid SSL certificate using LetsEncrypt for vpn.example.com and example.com using the web root of /var/www/html to validate the domains.
