# Local Check SSL expiration date

This script searches in a folder for files with the extension provided.

Every file found needs to be a certificate, the script will decode the file and get the data when it expires.

You can use this script with SNMP Extended and Icinga/Nagios or Zabbix

```
$ usage: SSL Check [-h] [-v] -c CRITICAL -w WARNING -p PATH -e EXTENSION
```

***Optional arguments:***
```
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
```

***Options:***

```
  -c CRITICAL, --critical CRITICAL

                                           Critical if cert expires in less than X days.
                                           Example: 10

  -w WARNING, --warning WARNING

                                           Warning if cert expires in less than X days.
                                           Example: 30

  -p PATH, --path PATH
                                           Path where crts are located.
                                           Example: /etc/nginx/ssl

  -e EXTENSION, --extension EXTENSION

                                           File extension to check.
                                           Example: .cer
```

***Outputs***

When the extension is not valid/file not found:
```
Error: No certificate found with extension '*cds'
```

When we have one ssl expired and one will expire soon:
```
CRITICAL: example.org expired on 2020-10-02, example2.org will expire on 2020-11-13 - 3 day(s) left
```

When one ssl will expire soon:
```
WARNING: example2.org will expire on 2020-11-13 - 3 day(s) left
```

When all certs are ok:
```
OK: All certs are ok. Monitoring domain(s): example.org, example2.org
```