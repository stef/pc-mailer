# This file contains python variables that configure Lamson for email processing.
import shelve
import logging
import os.path

# You may add additional parameters such as `username' and `password' if your
# relay server requires authentication, `starttls' (boolean) or `ssl' (boolean)
# for secure connections.
relay_config = {'host': 'localhost', 'port': 8825}

receiver_config = {'host': '', 'port': 25}

handlers = ['app.handlers.sample']

router_defaults = {'host': 'vps598.greenhost.nl'}

template_config = {'dir': 'app', 'module': 'templates'}

starttls=True

basepath=os.path.normpath(os.path.dirname(__file__)+'/../..')

sendermail="ono@vps598.greenhost.nl"

botjid="ono@xmpp.hsbp.org"

# the config/boot.py will turn these values into variables set in settings
