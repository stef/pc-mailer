#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging, re, base64, pgpdump, datetime, os, shutil, random
from lamson.routing import route, route_like, stateless
from lamson.encoding import to_message, to_string, from_string
from config.settings import relay, basepath, sendermail, botjid, webhost
from lamson import view
from email.utils import collapse_rfc2231_value
from sh import gpg
from dateutil.parser import parse as dparse
from lockfile import FileLock
from game import get_val, second, add_state, get_state
import struct, sys, hashlib, json

random.seed()

gpg=gpg.bake('--keyring', '%s/keys/keyring.pub' % basepath,
             '--homedir', '%s/.gnupg' % basepath,
             '--no-default-keyring',
             '--secret-keyring', '%s/keys/keyring.sec' % basepath)
def award(text):
    return gpg('--clearsign',
            '--armor',
            '--default-key',
            sendermail,
            _in="Achievement unlocked %s\n%s" % (text, datetime.datetime.utcnow().isoformat()))

def getpgpmeta(text):
    #logging.info(text)
    pgp_data=pgpdump.AsciiData(text)
    res={'sigs':[], 'ids': [], 'keys': []}
    try:
        for pkt in pgp_data.packets():
            #logging.info(pkt)
            if type(pkt)==pgpdump.packet.PublicKeyPacket:
                res['pubkey_version']= pkt.pubkey_version
                res['fingerprint']= pkt.fingerprint
                res['key_id']= pkt.key_id
                res['creation_time']= pkt.creation_time
                res['datetime']= pkt.datetime
                res['raw_pub_algorithm']= pkt.raw_pub_algorithm
                res['pub_algorithm']= pkt.pub_algorithm
                res['pub_algorithm_type']= pkt.pub_algorithm_type
            elif type(pkt)==pgpdump.packet.UserIDPacket:
                res['ids'].append({'user': pkt.user,
                                   'name': pkt.user_name,
                                   'email':pkt.user_email})
            elif type(pkt)==pgpdump.packet.SignaturePacket:
                res['sigs'].append({'sv': pkt.sig_version,
                                    'rst': pkt.raw_sig_type,
                                    'st': pkt.sig_type,
                                    'rpa': pkt.raw_pub_algorithm,
                                    'pa': pkt.pub_algorithm,
                                    'rha': pkt.raw_hash_algorithm,
                                    'ha': pkt.hash_algorithm,
                                    'ct': pkt.creation_time,
                                    'dt': pkt.datetime,
                                    'ki': pkt.key_id,
                                    'h2': pkt.hash2})
            elif type(pkt)==pgpdump.packet.PublicKeyEncryptedSessionKeyPacket:
                res['keys'].append({'key_id': pkt.key_id,
                                    'pub_algorithm': pkt.pub_algorithm,
                                    'raw_pub_algorithm': pkt.raw_pub_algorithm})
    except pgpdump.utils.PgpdumpException:
        pass
    return res

sendere=re.compile(r'(.*) {1,}<(\S*@\S*)>')

@route("upk@(host)")
@route("upload-public-key@(host)")
@stateless
def UPLOADPK(msg, address=None, host=None):
    res={}
    sender=collapse_rfc2231_value(msg['from'])
    m=sendere.match(sender)
    if m:
        res['sender_name'], res['sender_mail']=m.groups()
    else:
        res['sender_mail']=sender

    for mpart in msg.walk():
        ispgp=False
        part=to_message(mpart)
        if part.get_content_type()=='text/plain':
            # cut of preamble
            inblock=False
            lines=part.get_payload(decode=True).split('\n')
            i=0
            while i<len(lines):
                if not inblock:
                    if lines[i].strip()=='-----BEGIN PGP PUBLIC KEY BLOCK-----':
                        inblock=True
                        i+=2
                else:
                    if lines[i].strip()=='-----END PGP PUBLIC KEY BLOCK-----':
                        break
                i+=1
            if i<len(lines): ispgp=True
        elif part.get_content_type()=='application/pgp-keys':
            ispgp=True

        if ispgp:
            res=getpgpmeta(part.get_payload(decode=True))
            ret=gpg('--import',
                    _err_to_out=True,
                    _in=part.get_payload(decode=True))
            #logging.info(ret)
            modifiers={'fresh': False,
                       'abbreved': False,
                       'singleid': False,
                       'tidy': False,
                      }
            if res['datetime']>datetime.datetime.utcnow()-datetime.timedelta(days=10):
                modifiers['fresh']=True
            if len(res['ids'])<2:
                modifiers['singleid']=True
                if len(res['ids'][0]['email'].split('@')[0])<9:
                    modifiers['abbreved']=True
            if len([1 for x in res['sigs'] if x['st'] not in ['Positive certification of a User ID and Public Key packet', 'Subkey Binding Signature']])==0:
                modifiers['tidy']=True
            res['award']=award("You uploaded your public key.\n%s" % '\n'.join(["%s [%s]" % (k,'X' if v else ' ') for k,v in modifiers.items()]))
            #logging.info(res)
            welcome = view.respond(res, "pkuploaded.msg",
                           From=sendermail,
                           To=sender,
                           Subject="Welcome to the Privacy Challenge")
            view.attach(welcome, {}, "pubkey.asc", filename="my key", content_type="application/pgp-keys")
            relay.deliver(welcome)

signed1re=re.compile(r'gpg: Signature made (.*) using (.*) key ID (.*)$')
signed2re=re.compile(r'gpg: Good signature from "(.*) <(.*)>"')

@route("decoder@(host)")
@stateless
def DECODER(msg, address=None, host=None):
    sender=collapse_rfc2231_value(msg['from'])
    m=sendere.match(sender)
    res={}
    if m:
        res['sender_name'], res['sender_mail']=m.groups()
    else:
        res['sender_mail']=sender

    for mpart in msg.walk():
        part=to_message(mpart)
        # cut of preamble
        inblock=False
        lines=part.get_payload(decode=True).split('\n')
        i=0
        #logging.info(lines)
        while i<len(lines):
            if not inblock:
                if lines[i].strip()=='-----BEGIN PGP MESSAGE-----':
                    inblock=True
                    i+=2
            else:
                if lines[i].strip()=='-----END PGP MESSAGE-----':
                    break
            i+=1
        #logging.info(i)
        if i<len(lines):
            res.update(getpgpmeta(part.get_payload(decode=True)))
            ret=gpg('-d',
                    _ok_code=[0,2],
                    _in=part.get_payload(decode=True))
            #logging.info('ret '+str(ret))
            #logging.info('stderr '+ret.stderr)
            res['msg']='\n'.join(["> %s" % x for x in ret.stdout.split('\n')])
            # extra points,
            #   - no named recipient
            #   - signed
            modifiers={'sekrit': False, 'signed': False}
            #logging.info(res['keys'])
            if len([x for x in res['keys'] if x['key_id']!="0000000000000000"])==0:
                modifiers['sekrit']=True
            signed={}
            for line in ret.stderr.split('\n'):
                if line.startswith('gpg: Signature made '):
                    # gpg: Signature made Fri 11 May 2012 04:43:04 PM CEST using RSA key ID XXXXXX
                    m=signed1re.match(line)
                    if m:
                        #logging.info(m.groups())
                        signed['date']=dparse(str(m.group(1)))
                        signed['algo']=m.group(2)
                        signed['key_id']=m.group(3)
                elif line.startswith('gpg: Good signature from '):
                    # gpg: Good signature from "name <mail>"
                    m=signed2re.match(line)
                    if m:
                        #logging.info(m.groups())
                        signed['name']=m.group(1)
                        signed['mail']=m.group(2)
                    modifiers['signed']=True
            if signed: res['signed']=signed
            res['award']=award("You sent an encrypted mail.\n%s" % '\n'.join(["%s [%s]" % (k,'X' if v else ' ') for k,v in modifiers.items()]))
            #logging.info(res)
            welcome = view.respond(res, "pgpmail.msg",
                           From=sendermail,
                           To=sender,
                           Subject="Encrypted mail received")
            relay.deliver(welcome)

otrfpre=re.compile(r'(\S*@\S*)\s\s*([0-9a-fA-F]{8} [0-9a-fA-F]{8} [0-9a-fA-F]{8} [0-9a-fA-F]{8} [0-9a-fA-F]{8})$')

@route("otrfp@(host)")
@stateless
def otrfp(msg, address=None, host=None):
    sender=collapse_rfc2231_value(msg['from'])
    m=sendere.match(sender)
    res={}
    if m:
        res['sender_name'], res['sender_mail']=m.groups()
    else:
        res['sender_mail']=sender

    for mpart in msg.walk():
        part=to_message(mpart)
        # cut of preamble
        inblock=False
        lines=part.get_payload(decode=True).split('\n')
        i=0
        #logging.info(lines)
        while i<len(lines):
            if not inblock:
                if lines[i].strip()=='-----BEGIN PGP SIGNED MESSAGE-----' or lines[i].strip()=='-----BEGIN PGP MESSAGE-----':
                    inblock=True
                    i+=2
            else:
                if lines[i].strip()=='-----END PGP SIGNATURE-----' or lines[i].strip()=='-----END PGP MESSAGE-----':
                    break
            i+=1
        #logging.info(i)
        if i<len(lines):
            res.update(getpgpmeta(part.get_payload(decode=True)))
            ret=gpg('-d',
                    _ok_code=[0,2],
                    _in=part.get_payload(decode=True))
            #logging.info('ret '+str(ret))
            #logging.info('stderr '+ret.stderr)
            res['msg']='\n'.join(["> %s" % x for x in ret.stdout.split('\n')])
            # extra points,
            #   - no named recipient
            #   - signed
            #logging.info(res['keys'])
            modifiers={'sekrit': False, 'signed': False}
            if len([x for x in res['keys'] if x['key_id']!="0000000000000000"])==0:
                modifiers['sekrit']=True
            else: 
                logging.warn([x for x in res['keys'] if x['key_id']!="0000000000000000"])
            signed={}
            for line in ret.stderr.split('\n'):
                if line.startswith('gpg: Signature made '):
                    # gpg: Signature made Fri 11 May 2012 04:43:04 PM CEST using RSA key ID XXXXXX
                    m=signed1re.match(line)
                    if m:
                        #logging.info(m.groups())
                        signed['date']=dparse(str(m.group(1)))
                        signed['algo']=m.group(2)
                        signed['key_id']=m.group(3)
                elif line.startswith('gpg: Good signature from '):
                    # gpg: Good signature from "name <mail>"
                    m=signed2re.match(line)
                    if m:
                        #logging.info(m.groups())
                        signed['name']=m.group(1)
                        signed['mail']=m.group(2)
                    modifiers['signed']=True
            if not signed:
                plssign = view.respond(res, "plssign.msg",
                                       From=sendermail,
                                       To=sender,
                                       Subject="OTR fingerprint help")
                relay.deliver(plssign)
                continue
            res['signed']=signed
            res['award']=award("you bootstrapped OTR trust using PGP.\n%s" % '\n'.join(["%s [%s]" % (k,'X' if v else ' ') for k,v in modifiers.items()]))
            #logging.info(res)
            jid=None
            fp=None
            secret=None
            for line in to_message(from_string(ret.stdout)).get_payload(decode=True).split('\n'):
                if not line.strip(): continue
                if line=='-- ': break
                if jid and fp:
                    secret=line
                    break
                #logging.info("line "+line)
                m=otrfpre.match(line)
                if m:
                    #logging.info(m.groups())
                    jid, fp = m.group(1), m.group(2)
            if jid and fp:
                with FileLock('%s/otr/otr/%s.fpr' % (basepath, botjid)):
                    fr=open('%s/otr/otr/%s.fpr' % (basepath, botjid), 'r')
                    fw=open('%s/otr/otr/%s.fpr.new' % (basepath, botjid), 'w')
                    for line in fr:
                        #logging.info(line)
                        #logging.info("%s\t%s\tjabber\t%s" % (jid,
                        #                              botjid,
                        #                              fp.lower().replace(' ','')))
                        if line.startswith("%s\t%s\tjabber\t%s" % (jid,
                                                                   botjid,
                                                                   fp.lower().replace(' ',''))):
                            fw.write("%s\t%s\tjabber\t%s\ttrust\n" % (jid,
                                                                    botjid,
                                                                    fp.lower().replace(' ','')))
                        else:
                            fw.write(line)
                    fw.close()
                    fr.close()
                    os.unlink('%s/otr/otr/%s.fpr' % (basepath, botjid))
                    shutil.move('%s/otr/otr/%s.fpr.new' % (basepath, botjid),
                                '%s/otr/otr/%s.fpr' % (basepath, botjid))
            if secret:
                fs=open('%s/otr/otr/%s.s' % (basepath, jid), 'w')
                fs.write("%s %s" % (signed['key_id'], secret))
                fs.close()
            welcome = view.respond(res, "otrtrust.msg",
                           From=sendermail,
                           To=sender,
                           Subject="OTR fingerprint received")
            relay.deliver(welcome)

#@spam_filter(SPAM['db'], SPAM['rc'], SPAM['queue'], next_state=SPAMMING)
@route("ono@(host)")
def START(msg, host=None):
    sender=collapse_rfc2231_value(msg['from'])
    #subj=collapse_rfc2231_value(msg['subject'])
    resp = view.respond({}, "welcome.txt",
                        From=sendermail,
                        To=sender,
                        #Subject="Re: %s" % subj)
                        Subject="thanks! let's chat")
    relay.deliver(resp)
    return JITSI

@route("ono@(host)")
def JITSI(msg, host=None):
    sender=collapse_rfc2231_value(msg['from'])
    resp = view.respond({}, "jitsi.txt",
                        From=sendermail,
                        To=sender,
                        Subject="chatting continued")
    relay.deliver(resp)
    return SECRET

@route("ono@(host)")
def SECRET(msg, host=None):
    sender=collapse_rfc2231_value(msg['from'])
    resp = view.respond({'buddyurl': 'https://%s/buddy' % webhost},
                        "fetchsecret.txt",
                        From=sendermail,
                        To=sender,
                        Subject="getting serious")
    relay.deliver(resp)
    return XMPP

@route("ono@(host)")
def XMPP(msg, host=None):
    sender=collapse_rfc2231_value(msg['from'])
    resp = view.respond({}, "1stcontact.txt",
                        From=sendermail,
                        To=sender,
                        Subject="start chatting")
    relay.deliver(resp)
    return XMPP

@route("ono-dox-(mailid)@(host)")
@stateless
def doxer(msg, mailid=None, host=None):
    try:
        keyid=get_val('dox-mailid',":%s" % mailid, second)[:-(len(mailid)+1)]
    except TypeError:
        #print >>sys.stderr, 'nomailid'
        return # no such mailid
    pwd=get_state(keyid, 'prod.pdf.pass')
    #logging.info("pwd "+pwd)
    if not pwd:
        add_state(keyid, 'prod.pdf.err',"I got a mail, but i was not aware of the password at that time. try to resend it after telling me the password please.")
        return
    err = None
    for mpart in msg.walk():
        part=to_message(mpart)
        #if part.get_content_maintype() == 'multipart' or len(part.get_payload(decode=True)) < 268125:
        if part.get_content_maintype() == 'multipart':
            #print >>sys.stderr, 'skip', len(part.get_payload(decode=True) or ''), part.get_content_maintype()
            continue
        size = len(part.get_payload(decode=True))
        if (size < 200000 or size > 310000):
            continue
        hash=hashlib.sha256()
        def hupdate(data): # workaround for http://bugs.python.org/issue17481
            hash.update(data)
        ret=gpg('-d',
                '--passphrase', pwd,
                _ok_code=[0,2],
                _in=part.get_payload(decode=True),
                _out=hupdate)
        if ret.exit_code!=0:
            add_state(keyid, 'prod.pdf.err',"got a mail, but gpg had problems, try fixing the problem and resend the mail. gpg said this\n"+err)
            break
        #logging.info('ret '+str(ret))
        #logging.info('stderr '+ret.stderr)
        err=str(ret.stderr) # for flushing the process?
        #print >>sys.stderr, 'err', err
        if hash.hexdigest() == '658be96015645fe1d646fd167c1ac3bd372360530191d574ace5870c5aeb132f':
            add_state(keyid, 'prod.pdf.done','1')
            break
        else:
            add_state(keyid, 'prod.pdf.err',"got a mail, but it wasn't quite what i expected, so i dropped it.")
            break
    else:
        add_state(keyid, 'prod.pdf.err',"got a mail, but there was nothing found that looked like a reasonably sized pgp payload")

@route_like(START)
#@route(".+")
#@stateless
def FORWARD(message, address=None, host=None):
    relay.deliver(message)


