import ssl

import certifi

from consts import ORIGIN

req_headers_get=lambda sid, auth: [
    (':method', 'GET'),
    (':path', '/duh'),
    (':authority', ORIGIN),
    (':scheme', 'https'),
    ('user-agent', 'Mozilla/5.0 (Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0'),
    ('accept', '*/*'),
    ('accept-encoding', '*'),
    ('x-session-id', sid),
    ('x-ramen-auth', auth)
    ]

req_headers_post=lambda sid, auth: [
    (':method', 'POST'),
    (':path', '/duh'),
    (':authority', ORIGIN),
    (':scheme', 'https'),
    ('user-agent', 'Mozilla/5.0 (Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0'),
    ('accept', '*/*'),
    ('accept-encoding', '*'),
    ('content-type', 'application/octet-stream'),
    ('x-session-id', sid),
    ('x-ramen-auth', auth),
    ]

def get_ssl_ctx():
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.set_ciphers(':'.join([
        'TLS_AES_128_GCM_SHA256',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES256-SHA',
        'AES128-GCM-SHA256',
        'AES256-GCM-SHA384',
        'AES128-SHA',
        'AES256-SHA'
        ]))
    ctx.set_alpn_protocols(['h2'])
    return ctx