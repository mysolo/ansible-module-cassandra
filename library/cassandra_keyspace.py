#!/usr/bin/python
# -*- coding: utf-8 -*-
# TODO: add documentation here
try:
    import json
except ImportError:
    import simplejson as json
except:
    json_dep_found = False
else:
    json_dep_found = True

try:
    from cassandra.cluster import Cluster
    from cassandra.auth import PlainTextAuthProvider
    from cassandra.query import dict_factory
    from cassandra import InvalidRequest
except ImportError:
    cassandra_dep_found = False
else:
    cassandra_dep_found = True


ALTER_KEYSPACE_FORMAT = 'ALTER KEYSPACE {keyspace} WITH REPLICATION={config} AND DURABLE_WRITES={durable_writes}'
CREATE_KEYSPACE_FORMAT = 'CREATE KEYSPACE {keyspace} WITH REPLICATION={config} AND DURABLE_WRITES={durable_writes}'


def keyspace_management(module, session, keyspace, replication_strategy, durable_writes):
    changed = True
    keyspace_exist = True

    try:
        session.set_keyspace(keyspace)
    except InvalidRequest as e:
        keyspace_exist = False

    cql = (ALTER_KEYSPACE_FORMAT if keyspace_exist else CREATE_KEYSPACE_FORMAT)

    response = session.execute(cql.format(keyspace=keyspace,
                               config=json.dumps(replication_strategy).replace('"', '\''),
                               durable_writes=durable_writes))

    return changed, [{
        'query': response.response_future.message.query,
        'timestamp': response.response_future.message.timestamp,
        'opcode': response.response_future.message.opcode,
        'warnings': response.response_future.message.warnings,
        'consistency_level': response.response_future.message.consistency_level,
    }]


def main():

    arg_spec = {
        'keyspace': {
            'type': 'str',
            'required': True,
        },
        'replication_strategy': {
            'type': 'dict',
            'required': True,
        },
        'durable_writes': {
            'type': 'bool',
            'required': True,
        },
        'login_user': {
            'type': 'str',
            'required': True,
        },
        'login_password': {
            'type': 'str',
            'required': True,
            'no_log': True
        },
        'login_hosts': {
            'type': 'list',
            'required': True,
        },
        'login_port': {
            'type': 'int',
            'default': 9042,
            'required': False,
        },
        'protocol': {
            'type': 'int',
            'default': 3,
            'required': False,
        },
    }

    module = AnsibleModule(argument_spec=arg_spec)

    keyspace = module.params['keyspace']
    replication_strategy = module.params['replication_strategy']
    durable_writes = module.params['durable_writes']
    login_hosts = module.params['login_hosts']
    login_port = module.params['login_port']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    protocol = module.params['protocol']


    if not cassandra_dep_found:
        module.fail_json(msg="the python cassandra-driver module is required")

    if not json_dep_found:
        module.fail_json(msg="the python json or simplejson module is required")

    try:
        if not login_user:
            cluster = Cluster(login_hosts, port=login_port)

        else:
            auth_provider = PlainTextAuthProvider(username=login_user,
                                                  password=login_password)
            cluster = Cluster(login_hosts, auth_provider=auth_provider,
                              protocol_version=protocol, port=login_port)
        session = cluster.connect()
        session.row_factory = dict_factory
    except Exception, e:
        module.fail_json(
            msg="unable to connect to cassandra, check login_user and " +
                "login_password are correct. Exception message: %s"
                % e)

    changed, reasons = keyspace_management(module, session, keyspace, replication_strategy, durable_writes)

    module.exit_json(changed=changed, msg='OK', name=keyspace, reasons=reasons)

# Ansible "magic" (NOQA comments tells flake8 to ignore this line since it's
# bad Python, but required for Ansible)
from ansible.module_utils.basic import *  # NOQA
main()
