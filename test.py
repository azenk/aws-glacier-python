#!/usr/bin/env python

import aws.glacier

import sys

if sys.version < '3':
    import ConfigParser as configparser
else:
    import configparser

def main():
    profile = aws.glacier.Profile()
    print( profile.getHost() )

if __name__ == "__main__":
    main()
