import logging, re, base64, pgpdump, datetime
from lamson.routing import route, route_like, stateless
from lamson.encoding import to_message, to_string
from config.settings import relay, basepath, sendermail
from lamson import view
from email.utils import collapse_rfc2231_value
from pbs import gpg
from dateutil.parser import parse as dparse

gpg=gpg.bake('--keyring',
             '%s/keys/keyring.pub' % basepath,
             '--no-default-keyring',
             '--secret-keyring',
             '%s/keys/keyring.sec' % basepath)
def award(text):
    return gpg('--clearsign',
            '--armor',
            '--default-key',
            sendermail,
            _in="Achievement unlocked %s\n%s" % (text, datetime.datetime.utcnow().isoformat()))

def getpgpmeta(text):
    logging.info(text)
    pgp_data=pgpdump.AsciiData(text)
    res={'sigs':[], 'ids': [], 'keys': []}
    for pkt in pgp_data.packets():
        logging.info(pkt)
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
            logging.info(ret)
            modifiers=[]
            if res['datetime']>datetime.datetime.utcnow()-datetime.timedelta(days=10):
                modifiers.append('fresh')
            if len(res['ids'])<2:
                if len(res['ids'][0]['email'].split('@')[0])<9:
                    modifiers.append('abbreved')
                modifiers.append('singleid')
            modifiers.append('keyupper')
            res['award']=award("[%s] - you uploaded your public key." % '-'.join(modifiers))
            logging.info(res)
            welcome = view.respond(res, "pkuploaded.msg",
                           From=sendermail,
                           To=sender,
                           Subject="Welcome to the Privacy Challenge")
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
        logging.info(lines)
        while i<len(lines):
            if not inblock:
                if lines[i].strip()=='-----BEGIN PGP MESSAGE-----':
                    inblock=True
                    i+=2
            else:
                if lines[i].strip()=='-----END PGP MESSAGE-----':
                    break
            i+=1
        logging.info(i)
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
            modifiers=[]
            #logging.info(res['keys'])
            if len([x for x in res['keys'] if x['key_id']!="0000000000000000"])==0:
                modifiers.append('sekrit')
            signed={}
            for line in ret.stderr.split('\n'):
                if line.startswith('gpg: Signature made '):
                    # gpg: Signature made Fri 11 May 2012 04:43:04 PM CEST using RSA key ID XXXXXX
                    m=signed1re.match(line)
                    if m:
                        logging.info(m.groups())
                        signed['date']=dparse(str(m.group(1)))
                        signed['algo']=m.group(2)
                        signed['key_id']=m.group(3)
                elif line.startswith('gpg: Good signature from '):
                    # gpg: Good signature from "name <mail>"
                    m=signed2re.match(line)
                    if m:
                        logging.info(m.groups())
                        signed['name']=m.group(1)
                        signed['mail']=m.group(2)
                    modifiers.append('signed')
            if signed: res['signed']=signed
            modifiers.append('encrypter')
            res['award']=award("[%s] - you sent an encrypted mail." % '-'.join(modifiers))
            logging.info(res)
            welcome = view.respond(res, "pgpmail.msg",
                           From=sendermail,
                           To=sender,
                           Subject="Encrypted mail received")
            relay.deliver(welcome)

#@route_like(START)
#@stateless
#def FORWARD(message, address=None, host=None):
#    relay.deliver(message)

