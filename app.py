"""
GitHub WebHook receiver for AWS Lambda OR local runner.
WARNING: webhook events are delivered at-least-once, not exactly-once.

AWS:
Python based AWS lambda function that receives GitHub WebHooks
and publishes them to SNS topics.

Local:
Push GitHub Webhooks to some storage
"""

# core
import base64
import datetime
import gzip
import hashlib
import hmac
import json
import os
import re
from ipaddress import ip_address, ip_network

# installed
import boto3
from chalice import BadRequestError, Chalice, UnauthorizedError

GITHUB_API_META = 'https://api.github.com/meta'

DEFAULTS = {
        'S3_REGION': 'eu-west-1',
        # TODO: whitelist instead?
        'HASHLIB_BLACKLIST': ['CRC32', 'CRC32C', 'MD4', 'MD5', 'MDC2'],
        'SRC_IP_WHITELIST': ['127.0.0.0/8', '::1/128', GITHUB_API_META],
        'TOPIC_FORMAT': '{integration}_{event}',
}

CONFIG = {
    'DEBUG': os.environ.get('DEBUG', '') in [1, '1', 'True', 'true'],
    'SECRET': os.environ.get('SECRET'),
    'S3_REGION': os.environ.get('S3_REGION', DEFAULTS['S3_REGION']),
    'HASHLIB_BLACKLIST': os.environ.get('HASHLIB_BLACKLIST', DEFAULTS['HASHLIB_BLACKLIST']),
    # Whitelist of source IPs for request. Either IP or URLs supported (to
    # allow dynamic fetch).
    'SRC_IP_WHITELIST': os.environ.get('SRC_IP_WHITELIST', DEFAULTS['SRC_IP_WHITELIST']),
    'TOPIC_FORMAT': os.environ.get('TOPIC_FORMAT', DEFAULTS['TOPIC_FORMAT']),
}

if isinstance(CONFIG['HASHLIB_BLACKLIST'], str):
    _ = re.split('[;,\s]+', CONFIG['HASHLIB_BLACKLIST'])
    CONFIG['HASHLIB_BLACKLIST'] = set(map(lambda s: s.strip().lower(), _))
if isinstance(CONFIG['SRC_IP_WHITELIST'], str):
    CONFIG['SRC_IP_WHITELIST'] = set(re.split('\s+', CONFIG['SRC_IP_WHITELIST']))

app = Chalice(app_name='github-webhooks')
app.debug = CONFIG['DEBUG']

SNS = boto3.client('sns', region_name=CONFIG['S3_REGION'])


def validate_signature(request):
    """Validate that the signature in the header matches the payload."""
    if CONFIG['SECRET'] is None:
        return
    try:
        signature = request.headers['X-Hub-Signature']
        hashname, hashval = signature.split('=')
    except (KeyError, ValueError):
        raise BadRequestError()
    if (hashname in CONFIG['HASHLIB_BLACKLIST']) or \
            (hashname not in hashlib.algorithms_available):
        raise UnauthorizedError('X-Hub-Signature hash unavailable')

    digest = hmac.new(CONFIG['SECRET'], request.raw_body, hashname) \
        .hexdigest()
    if not hmac.compare_digest(digest, hashval.encode('utf-8')):
        raise UnauthorizedError('X-Hub-Signature mismatch')

def validate_source(request):
    """Validate source IP for request."""
    from pprint import pprint
    src_ip = ip_address(request.context.get('identity').get('sourceIp'))
    for whitelist_entry in CONFIG['SRC_IP_WHITELIST']:
        valid_ip_blocks = []
        if whitelist_entry.startswith('http://') or whitelist_entry.startswith('https://'):
            try:
                doc_raw = requests.get(whitelist_entry)
                doc_json = doc_raw.json()
                valid_ip_blocks = doc_json['hooks']
            except:
                pass
        else:
            valid_ip_blocks = [whitelist_entry]
        if any(map(lambda x: src_ip in ip_network(x, strict=False), valid_ip_blocks)):
            return

    raise UnauthorizedError('Unauthorized source')

@app.route('/{integration}', methods=['POST'])
def index(integration):
    """Consume GitHub webhook and publish hooks to destination"""
    request = app.current_request
    validate_signature(request)
    validate_source(request)
    # TODO:detect Local vs WS
    (ar, lr) = (None, None)
    # TODO: make sure we push errors back up to GitHub
    lr = local_index(integration)
    #ar = aws_index(integration)
    return [ar, lr]

def logging_payload(request):
    return {
            'json': request.json_body,
            'raw,base64+gzip': base64.encodestring(gzip.compress(request.raw_body)).decode('ascii'),
            'headers': dict(request.headers),
            'context': request.context,
            }

def local_index(integration):
    request = app.current_request
    # TODO: add stdout+stderr keys to return for debugging
    d = datetime.datetime.utcnow()
    epoch = d.timestamp()
    fn = '/tmp/json/{year}/{year}-{month}/{year}-{month}-{day}/'.format(
            year=d.year,
            month=('%02d' % d.month),
            day=('%02d' % d.day)
            )
    if not os.path.isdir(fn):
        os.makedirs(fn)
    fn = os.path.join(fn, '.'.join([request.headers['X-GitHub-Delivery'], str(epoch), 'json']))
    with open(fn, "a") as f:
        f.write(json.dumps(logging_payload(request)))
    return {'Code': 'Ok', 'Message': 'Webhook received.'}

def aws_index(integration):
    """Consume GitHub webhook and publish hooks to AWS SNS."""
    request = app.current_request
    try:
        event = request.headers['X-GitHub-Event']
    except KeyError:
        raise BadRequestError()
    sns_topics = SNS.list_topics()['Topics']
    topic_arns = {
        t['TopicArn'].rsplit(':')[-1]: t['TopicArn']
        for t in sns_topics
        }

    # TODO: Yep, this is a sec vuln
    # But we need some way to configure the topic better
    topic = CONFIG['TOPIC_FORMAT'].format(**vars())
    if topic not in topic_arns.keys():
        topic_arns[topic] = SNS.create_topic(Name=topic)['TopicArn']

    SNS.publish(
        TargetArn=topic_arns[topic],
        Subject=event,
        #Message=json.dumps({'default': json.dumps(request.json_body)}),
        Message=json.dumps({'default': json.dumps(logging_payload(request))}),
        MessageStructure='json'
    )

    # TODO: add stdout+stderr keys to return for debugging
    return {'Code': 'Ok', 'Message': 'Webhook received.'}
