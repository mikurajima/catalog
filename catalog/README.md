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
OS version `Ubuntu VERSION="16.04.4 LTS (Xenial Xerus)"`<br>
DataBase version `mysql	14.14 bistrib 5.7.27`<br>
Web Server version: `Apache/2.4.18 (Ubuntu)`<br>
Program version `python3 3.5.2`<br>
<br>
`blinker             1.3`<br>
`chardet             2.3.0`<br>
`Click               7.0`<br>
`cloud-init          17.2`<br>
`command-not-found   0.3`<br>
`configobj           5.0.6`<br>
`cryptography        1.2.3`<br>
`Flask               1.1.1`<br>
`hibagent            1.0.1`<br>
`idna                2.0`<br>
`itsdangerous        1.1.0`<br>
`Jinja2              2.10.1`<br>
`jsonpatch           1.10`<br>
`jsonpointer         1.9`<br>
`language-selector   0.1`<br>
`MarkupSafe          0.23`<br>
`oauthlib            1.0.3`<br>
`pip                 19.2.3`<br>
`prettytable         0.7.2`<br>
`pyasn1              0.1.9`<br>
`pycurl              7.43.0`<br>
`pygobject           3.20.0`<br>
`PyJWT               1.3.0`<br>
`pyserial            3.0.1`<br>
`python-apt          1.1.0b1+ubuntu0.16.4.1`<br>
`python-debian       0.1.27`<br>
`python-systemd      231`<br>
`PyYAML              3.11`<br>
`requests            2.9.1`<br>
`setuptools          20.7.0`<br>
`six                 1.10.0`<br>
`ssh-import-id       5.5`<br>
`ufw                 0.35`<br>
`unattended-upgrades 0.1`<br>
`urllib3             1.13.1`<br>
`Werkzeug            0.15.6`<br>
`wheel               0.29.0`<br>
<br>
import string<br>
import random<br>
from httplib2 import Http<br>
import requests<br>
from flask import session as login_session<br>
from flask import make_response<br>
import httplib2<br>
from oauth2client.client import FlowExchangeError<br>
from oauth2client.client import flow_from_clientsecrets<br>
from flask_httpauth import HTTPBasicAuth<br>
import json<br>
from datetime import datetime<br>
from models import Base, Items, User, Category<br>
from sqlalchemy.orm import sessionmaker<br>
from sqlalchemy import create_engine, asc, desc<br>
from flask import Flask, render_template, request, redirect, jsonify, url_for<br>
from flask import flash<br>

## Contributing

## SSH key location
`/home/grader/.ssh/grader`

## Code Status
Build

## Notes to Reviewer


## License
