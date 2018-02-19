import re

from flask import request

SCOPE_RE = re.compile(r'^(?P<type>repository):(?P<name>[^:]+)(?::(?P<tag>[^:]))?:(?P<actions>.*)$')


def parse_scope(scope):
    parsed = SCOPE_RE.match(scope.strip().lower())
    return {
        'type': parsed.group('type'),
        'name': parsed.group('name'),
        'tag': parsed.group('tag'),
        'actions': parsed.group('actions').split(','),
    }


def get_scopes():
    scopes = list()
    for s in request.args.getlist('scope'):
        scopes.append(parse_scope(s))
    return scopes
