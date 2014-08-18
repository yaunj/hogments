#!/usr/bin/env python
# coding: utf-8
#
# License: BSD; see LICENSE for more details.
from pygments.lexer import RegexLexer, include, bygroups
import pygments.token as t

class SnortLexer(RegexLexer):
    name = 'Snort'
    aliases = ['snort', 'hog']
    filenames = ['*.rules']

    tokens = {
        'root': [
            (r'#.*$', t.Comment),
            (r'(\$\w+)', t.Name.Variable),
            (r'\b(any|(\d{1,3}\.){3}\d{1,3}(/\d+)?)', t.Name.Variable),
            (r'^\s*(log|pass|alert|activate|dynamic|drop|reject|sdrop|'
             r'ruletype|var|portvar|ipvar)',
                t.Keyword.Type),
            (r'\b(metadata)(?:\s*:)', t.Keyword, 'metadata'),
            (r'\b(reference)(?:\s*:)', t.Keyword, 'reference'),
            (r'\b(msg|reference|gid|sid|rev|classtype|priority|metadata|'
             r'content|http_encode|uricontent|urilen|isdataat|pcre|pkt_data|'
             r'file_data|base64_decode|base64_data|byte_test|byte_jump|'
             r'byte_extract|ftp_bounce|pcre|asn1|cvs|dce_iface|dce_opnum|'
             r'dce_stub_data|sip_method|sip_stat_code|sip_header|sip_body|'
             r'gtp_type|gtp_info|gtp_version|ssl_version|ssl_state|nocase|'
             r'rawbytes|depth|offset|distance|within|http_client_body|'
             r'http_cookie|http_raw_cookie|http_header|http_raw_header|'
             r'http_method|http_uri|http_raw_uri|http_stat_code|'
             r'http_stat_msg|fast_pattern|fragoffset|fragbits|'
             r'ttl|tos|id|ipopts|dsize|flags|flow|flowbits|seq|ack|window|'
             r'itype|icode|icmp_id|icmp_seq|rpc|ip_proto|sameip|'
             r'stream_reassemble|stream_size|logto|session|resp|react|tag|'
             r'activates|activated_by|replace|detection_filter|treshold)'
             r'(?:\s*:)',
                t.Keyword),
            (r'\b(tcp|udp|icmp|ip)', t.Keyword.Constant),
            (r'\b(hex|dec|oct|string|type|output|any|engine|soid|service|'
             r'norm|raw|relative|bytes|big|little|align|invalid-entry|'
             r'enable|disable|client|server|both|either|printable|binary|'
             r'all|session|host|packets|seconds|bytes|src|dst|track|by_src|'
             r'by_dst|uri|header|cookie|utf8|double_encode|non_ascii|'
             r'uencode|bare_byte|ascii|iis_encode|bitstring_overflow|'
             r'double_overflow|oversize_length|absolute_offset|'
             r'relative_offset|rr|eol|nop|ts|sec|esec|lsrr|lsrre|'
             r'ssrr|satid|to_client|to_server|from_client|from_server|'
             r'established|not_established|stateless|no_stream|only_stream|'
             r'no_frag|only_frag|set|setx|unset|toggle|isset|isnotset|'
             r'noalert|limit|treshold|count|str_offset|str_depth|tagged)',
                t.Name.Attribute),
            (r'(<-|->|<>)', t.Operator),
            (ur'”', t.String, 'fancy-string'),
            (ur'“', t.String, 'fancy-string'),
            (r'"', t.String, 'dq-string'),
            (r'\'', t.String, 'sq-string'),
            (r'(\d+)', t.Number),
            (r';', t.Punctuation),
            (r'\\', t.String.Escape),
            (r'\s+', t.Whitespace),
        ],
        'hex': [
            (r'\|([a-fA-F0-9 ]+)\|', t.Number.Hex),
        ],
        'dq-string': [
            include('hex'),
            (r'([^"])', t.String),
            (r'"', t.String, '#pop')
        ],
        'sq-string': [
            include('hex'),
            (r'([^\'])', t.String),
            (r'\'', t.String, '#pop')
        ],
        'fancy-string': [
            include('hex'),
            (ur'([^”])', t.String),
            (ur'”', t.String, '#pop')
        ],
        'metadata': [
            (r'\s', t.Whitespace),
            (r'([\w_-]+)(\s+)([\w_-]+)',
                bygroups(t.Name.Variable, t.Whitespace, t.Name.Attribute)),
            (r';', t.Punctuation, '#pop'),
        ],
        'reference': [
            (r'(\w+)(,)(?:\s*)([^;]+)',
                bygroups(t.Name.Variable, t.Punctuation, t.Name.Attribute)),
            (r';', t.Punctuation, '#pop')
        ]
    }

if __name__ == '__main__':
    from pygments import highlight
    from pygments.formatters import Terminal256Formatter
    from sys import argv

    if len(argv) > 1:
        import io

        for arg in argv[1:]:
            input = io.open(arg, 'r')
            code = input.read(-1)
            print("Highlighting " + arg)
            print(highlight(code, SnortLexer(encoding='chardet'),
                  Terminal256Formatter(encoding='utf-8')))

    else:
        code = """
alert tcp $HOME_NET any -> 192.168.1.0/24 111 (content:"|00 01 86 a5|"; msg: "mountd access";)
alert tcp any any -> any 21 (content:"site exec"; content:"%"; msg:"site exec buffer overflow attempt";)
alert tcp !192.168.1.0/24 any -> 192.168.1.0/24 111 (content: "|00 01 86 a5|"; msg: "external mountd access";)
"""
        print(highlight(code, SnortLexer(), Terminal256Formatter()))
