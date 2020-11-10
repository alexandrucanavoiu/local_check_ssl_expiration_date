#!/usr/bin/env python3
#
# Local Check SSL expiration date
#
# Last Modified: 2020-11-10
#
# Usage: SSL Check [-h] [-v] -c CRITICAL -w WARNING -p PATH -e EXTENSION
#
# Outputs:
#
# CRITICAL: example.org expired on 2020-10-02, example2.org will expire on 2020-11-13 - 3 day(s) left
# WARNING: example2.org will expire on 2020-11-13 - 3 day(s) left
# OK: All certs are ok. Monitoring domain(s): example.org, example2.org
#
# Copyright (C) by Alexandru Canavoiu (alex.canavoiu@marketingromania.ro) used under MIT license
#

import sys

try:
    import OpenSSL.crypto
    import os
    import argparse
    import pathlib

    from pathlib import Path
    from datetime import datetime, timedelta, date

except ImportError as e:
    print("Missing python module: {}".format(e.message))
    sys.exit(255)


def dir_path(path):
    p = pathlib.Path(path)
    if p.is_dir():
        return p
    raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")

parser = argparse.ArgumentParser(
    description="""
                   Check SSL expiration date
                   -------------------------

This script searches in a folder for files with the extension provided.
Every file found needs to be a certificate, the script will decode the file and get the data when it expires.
You can use this script with SNMP Extended and Icinga/Nagios or Zabbix
                   """,
    prog="SSL Check",
    formatter_class=argparse.RawTextHelpFormatter,
)

parser.add_argument("-v", "--version", action="version", version="%(prog)s version 0.1")

opts = parser.add_argument_group("Options")

opts.add_argument(
    "-c",
    "--critical",
    type=int,
    required=True,
    help="""
                   Critical if cert expires in less than X days.
                   Example: 10
                   """,
)
opts.add_argument(
    "-w",
    "--warning",
    type=int,
    required=True,
    help="""
                   Warning if cert expires in less than X days.
                   Example: 30
                   """,
)
opts.add_argument(
    "-p",
    "--path",
    type=dir_path,
    required=True,
    help="""
                   Path where crts are located.
                   Example: /etc/nginx/ssl
                   """,
)
opts.add_argument(
    "-e",
    "--extension",
    required=True,
    help="""
                   File extension to check.
                   Example: .cer
                   """,
)
def main():
    args = parser.parse_args()


    warning_days = args.warning
    critical_days = args.critical
    path_folder = args.path
    extension_file = "*" + args.extension

    datetoday = date.today()
    current_date = datetoday.strftime("%Y-%m-%d")

    domains_name = []
    expire_list = []
    exit_code = [0]
    path_count = 0

    for path in Path(path_folder).rglob(extension_file):
        try:
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, path.read_bytes()
            )
        except OpenSSL.crypto.Error as e:
            return f"whatever {path} was, it wasn't a cert"

        for subject_component in cert.get_subject().get_components():
            if b"CN" in subject_component:
                for CN_component in subject_component:
                    if not CN_component == b"CN":
                        domains_name.append(CN_component.decode("utf8"))
                        domain_name = CN_component.decode("utf8")
        certificate_expiration_date = datetime.strptime(
            cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ"
        )
        certificate_expiration_date_warning = certificate_expiration_date - timedelta(
            days=warning_days
        )
        certificate_expiration_date_critical = certificate_expiration_date - timedelta(
            days=critical_days
        )

        days_until_expire = certificate_expiration_date.date() - datetoday
        path_count += 1

        if certificate_expiration_date.strftime("%Y-%m-%d") < current_date:
            expire_list.append(
                "{} expired on {}".format(
                    domain_name, certificate_expiration_date.strftime("%Y-%m-%d")
                )
            )
            exit_code.append(2)

        elif certificate_expiration_date_critical.strftime("%Y-%m-%d") <= current_date:
            expire_list.append(
                "{} will expire on {} - {} day(s) left".format(
                    domain_name,
                    certificate_expiration_date.strftime("%Y-%m-%d"),
                    days_until_expire.days,
                )
            )
            exit_code.append(2)

        elif certificate_expiration_date_warning.strftime("%Y-%m-%d") < current_date:
            expire_list.append(
                "{} will expire on {} - {} day(s) left".format(
                    domain_name,
                    certificate_expiration_date.strftime("%Y-%m-%d"),
                    days_until_expire.days,
                )
            )
            exit_code.append(1)

    exit_code = max(exit_code)

    if path_count == 0:
        print("Error: No certificate found with extension '{}'".format(extension_file))
        exit_code = 2
    elif expire_list:
        if exit_code == 1:
            code = "WARNING: "
        elif exit_code == 2:
            code = "CRITICAL: "
        else:
            code = ""
        print(code + ", ".join([str(item) for item in expire_list]))
    elif not expire_list:
        print(
            "OK: All certs are ok. Monitoring domain(s): {}".format(
                ", ".join(domains_name[1::2])
            )
        )
    return exit_code

if __name__ == "__main__":
    sys.exit(main())