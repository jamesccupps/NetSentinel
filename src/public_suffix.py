"""
Registrable domains.
====================
"example.co.za" is one owner's domain; "co.za" is not anyone's. Learning a domain
as normal by its last two labels made one site under .co.za, or one tenant of
github.io, whitelist every other one.

The built-in list covers the multi-label country suffixes and the shared platforms
(hosting, dynamic DNS, tunnels) that come up in real traffic. Put Mozilla's full
list at ~/.netsentinel/data/public_suffix_list.dat to use it instead; it is read
once, at the first lookup.
"""

import os
import threading

_BUILTIN = """
co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk net.uk nhs.uk sch.uk police.uk
com.au net.au org.au edu.au gov.au asn.au id.au
co.nz net.nz org.nz govt.nz ac.nz school.nz geek.nz
co.za org.za gov.za ac.za net.za web.za
co.jp ne.jp or.jp ac.jp go.jp ad.jp ed.jp gr.jp lg.jp
co.in net.in org.in gov.in ac.in edu.in res.in firm.in gen.in ind.in
com.br net.br org.br gov.br edu.br art.br
com.cn net.cn org.cn gov.cn edu.cn ac.cn
com.mx org.mx gob.mx edu.mx net.mx
com.ar gob.ar org.ar net.ar edu.ar
com.tr org.tr gov.tr edu.tr net.tr bel.tr
co.kr or.kr go.kr ac.kr ne.kr re.kr
com.sg org.sg gov.sg edu.sg net.sg
com.hk org.hk gov.hk edu.hk net.hk idv.hk
com.tw org.tw gov.tw edu.tw net.tw idv.tw
com.my org.my gov.my edu.my net.my
co.id or.id go.id ac.id web.id net.id
com.ph org.ph gov.ph edu.ph net.ph
co.th or.th go.th ac.th in.th net.th
com.vn org.vn gov.vn edu.vn net.vn
com.pk org.pk gov.pk edu.pk net.pk
com.sa org.sa gov.sa edu.sa net.sa
com.eg org.eg gov.eg edu.eg net.eg
co.il org.il gov.il ac.il net.il muni.il
com.ua org.ua gov.ua net.ua in.ua
com.pl org.pl net.pl gov.pl edu.pl
co.at or.at gv.at ac.at
com.es org.es gob.es edu.es nom.es
com.pt org.pt gov.pt edu.pt
com.gr org.gr gov.gr edu.gr
com.ru org.ru net.ru msk.ru spb.ru
co.ke or.ke go.ke ac.ke
com.ng org.ng gov.ng edu.ng
com.co org.co gov.co edu.co net.co
com.pe org.pe gob.pe edu.pe
co.ve com.ve org.ve gob.ve
com.uy org.uy gub.uy edu.uy
co.cr or.cr go.cr ac.cr
github.io githubusercontent.com gitlab.io bitbucket.io pages.dev workers.dev
r2.dev netlify.app vercel.app herokuapp.com fly.dev onrender.com glitch.me
firebaseapp.com web.app appspot.com cloudfunctions.net run.app
azurewebsites.net cloudapp.net azurestaticapps.net blob.core.windows.net
trafficmanager.net azureedge.net azurefd.net
amazonaws.com *.amazonaws.com s3.amazonaws.com *.compute.amazonaws.com
compute-1.amazonaws.com elasticbeanstalk.com *.elasticbeanstalk.com
cloudfront.net awsapprunner.com amplifyapp.com
blogspot.com wordpress.com tumblr.com wixsite.com weebly.com squarespace.com
myshopify.com webflow.io carrd.co notion.site
duckdns.org no-ip.org no-ip.com ddns.net dynu.net hopto.org zapto.org
sytes.net serveftp.com freedns.org afraid.org dyndns.org mooo.com
ngrok.io ngrok-free.app ngrok.app trycloudflare.com loca.lt serveo.net
repl.co replit.dev codesandbox.io stackblitz.io
"""

_lock = threading.Lock()
_rules = None


def _load():
    global _rules
    with _lock:
        if _rules is not None:
            return _rules
        lines = _BUILTIN.split()
        try:
            from src.config import DB_DIR
            path = os.path.join(DB_DIR, 'public_suffix_list.dat')
            if os.path.exists(path):
                with open(path, encoding='utf-8') as f:
                    lines = [line.split()[0] for line in f
                             if line.strip() and not line.startswith('//')]
        except OSError:
            pass
        exact, wildcard, exceptions = set(), set(), set()
        for rule in (r.lower() for r in lines):
            if rule.startswith('!'):
                exceptions.add(rule[1:])
            elif rule.startswith('*.'):
                wildcard.add(rule[2:])
            else:
                exact.add(rule)
        _rules = (exact, wildcard, exceptions)
        return _rules


def public_suffix(name):
    """The longest public suffix of a name, by the public-suffix algorithm."""
    exact, wildcard, exceptions = _load()
    labels = name.lower().strip('.').split('.')
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in exceptions:
            return '.'.join(labels[i + 1:])
        if candidate in exact:
            return candidate
        parent = '.'.join(labels[i + 1:])
        if parent in wildcard:
            return candidate
    return labels[-1]   # an unlisted TLD is its own suffix


def registrable_domain(name):
    """
    The part someone registered: one label above the public suffix.

    None when the name is itself a public suffix ("github.io", "co.uk"), since
    nobody owns those and they must not be learned as one domain.
    """
    name = (name or '').lower().strip('.')
    if not name:
        return None
    suffix = public_suffix(name)
    if name == suffix:
        return None
    rest = name[:-len(suffix) - 1]
    return f"{rest.rsplit('.', 1)[-1]}.{suffix}"
