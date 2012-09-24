#!/usr/bin/env python

import aws.glacier

import sys
import argparse
import json

if sys.version < '3':
    import ConfigParser as configparser
else:
    import configparser

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--accesskey',dest='accesskey')
    parser.add_argument('--secret', dest='secret')
    parser.add_argument('--debug', action='store_true',default=False, dest='debug')

    args = parser.parse_args()

    profile = aws.glacier.Profile(access_id=args.accesskey,key=args.secret,debug=args.debug)
    vaults = aws.glacier.Vault.getVaults(profile)
    for vault in vaults:
        print(vault.properties['VaultARN'])
    testvault = aws.glacier.Vault(profile,"testvault")
    print(testvault.getProperties())


if __name__ == "__main__":
    main()
