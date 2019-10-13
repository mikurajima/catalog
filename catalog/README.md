# Udacity Fullstack Project 2
This is an assigned project 2nd by Udacity that is for fullstack web developer nanodegree program.
It is a catalog web application that allows user CURD items and cetegory with OAuth
## Installation
Place this folder at your vagrant holder.  
vagrant is not working where the holder name uses Chinese character (Kanji).  
At windows, please turn off hypervisor auto start, otherwise vagrant is not working.
## Usage
access `52.195.9.148.xip.io/` to start
port for ssh is `52.195.9.148:2200`
## list of software
Ubuntu VERSION="16.04.4 LTS (Xenial Xerus)"
mysql	14.14 bistrib 5.7.27
Server version: Apache/2.4.18 (Ubuntu)
python3	3.5.2

`blinker             1.3`
`chardet             2.3.0`
`Click               7.0`
`cloud-init          17.2`
`command-not-found   0.3`
`configobj           5.0.6`
`cryptography        1.2.3`
`Flask               1.1.1`
`hibagent            1.0.1`
`idna                2.0`
`itsdangerous        1.1.0`
`Jinja2              2.10.1`
`jsonpatch           1.10`
`jsonpointer         1.9`
`language-selector   0.1`
`MarkupSafe          0.23`
`oauthlib            1.0.3`
`pip                 19.2.3`
`prettytable         0.7.2`
`pyasn1              0.1.9`
`pycurl              7.43.0`
`pygobject           3.20.0`
`PyJWT               1.3.0`
`pyserial            3.0.1`
`python-apt          1.1.0b1+ubuntu0.16.4.1`
`python-debian       0.1.27`
`python-systemd      231`
`PyYAML              3.11`
`requests            2.9.1`
`setuptools          20.7.0`
`six                 1.10.0`
`ssh-import-id       5.5`
`ufw                 0.35`
`unattended-upgrades 0.1`
`urllib3             1.13.1`
`Werkzeug            0.15.6`
`wheel               0.29.0`

import string
import random
from httplib2 import Http
import requests
from flask import session as login_session
from flask import make_response
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from flask_httpauth import HTTPBasicAuth
import json
from datetime import datetime
from models import Base, Items, User, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, asc, desc
from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash

## Contributing

## SSH key location
`/home/grader/.ssh/grader`

## Code Status
Build

## Notes to Reviewer


## License
