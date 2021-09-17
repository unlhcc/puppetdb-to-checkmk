#!/usr/bin/env python
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

""" Sync hosts from puppetdb to checkmk using API

    - get list from puppetdb and checkmk
    - add missing hosts to checkmk, add magic puppetdb label if necessary
    - delete extras (only if magic puppetdb label present) from checkmk
    - profit!
"""

import argparse
import dns.resolver
import json
import logging
import pprint
import requests
import socket
import yaml

# FIXME: Resolve this in a better/more elegant way
# https://stackoverflow.com/questions/38015537/python-requests-exceptions-sslerror-dh-key-too-small
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'

parser = argparse.ArgumentParser()
parser.add_argument('--config', type=argparse.FileType('r'),
                    default='config.yaml', help='YAML config (default config.yaml)')
args = parser.parse_args()
config = yaml.safe_load(args.config)


logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)


def get_all_hosts_checkmk():
    """ Get existing hosts in checkmk and return dict
        containing { hostname: { dict of hostlabels } }
    """

    checkmk_api_url = config['checkmk_api_url']

    req_params = { 'action': 'get_all_hosts',
        '_username': config['checkmk_api_username'],
        '_secret': config['checkmk_api_secret'],
        'effective_attributes': '1',
        'output_format': 'json' }
    r = requests.post(checkmk_api_url, req_params)

    hosts = {}
    for host in r.json()['result'].items():
        hostname = host[0]
        hostlabels = host[1]['attributes']['labels']
        hosts[hostname] = hostlabels

    logging.info('got %s hosts from checkmk', len(hosts))

    return hosts


def get_all_hosts_puppetdb():
    """ Get existing hosts in puppetdb and return dict containing
        { hostname: { dict of hostlabels to ensure present in checkmk } }
    """

    puppetdb_api_url = config['puppetdb_api_url']
    puppetdb_certfile = config.get('puppetdb_certfile', None)
    puppetdb_keyfile = config.get('puppetdb_keyfile', None)
    puppetdb_cafile = config.get('puppetdb_cafile', None)

    # query to match only puppet hosts with Check_mk::Agent class
    query = {
        'query': ['=', 'type', 'Check_mk::Agent'],
    }

    r = requests.post(puppetdb_api_url, json=query,
        cert=(puppetdb_certfile, puppetdb_keyfile), verify=puppetdb_cafile)

    hosts = {}
    for res in r.json():
        tags = res['tags']
        hostname = res['certname']
        host_environment = res['environment']
        for tag in res['tags']:
            if tag.startswith('roles::') or tag.startswith('role::'):
                host_role = tag.split('::')[1]
        hosts[hostname] = { 'puppet_environment': host_environment,
            'puppet_role': host_role }

    logging.info('got %s hosts from puppetdb', len(hosts))

    return hosts


def add_host_to_checkmk(hostname, hostlabels):
    """ Add host to checkmk with any hostlabels from puppetdb, adding label of
        from_puppetdb=<label> to help indicate host was added by this script
    """

    logging.debug('going to add %s with hostlabels %s' % (hostname, hostlabels))

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']
    checkmk_default_folder = config['checkmk_default_folder']
    checkmk_default_location = config['checkmk_default_location']
    checkmk_puppetdb_label = config['checkmk_puppetdb_label']

    hostlabels['from_puppetdb'] = checkmk_puppetdb_label

    # Determine if host is dual stacked v4/v6 and include ip-v4v6
    # address_family if so, else leave address_family off to use default
    try:
        d = dns.resolver.resolve(hostname, 'AAAA')
        logging.debug('-- host appears dual stacked, adding ip-v4v6')
        payload = {'request': json.dumps({
            'hostname': hostname,
            'folder': checkmk_default_folder,
            'attributes': {
                'tag_location': checkmk_default_location,
                'tag_address_family': 'ip-v4v6',
                'labels': hostlabels
                }
            })}
    except Exception as e:
        logging.debug('-- host not dual stacked')
        payload = {'request': json.dumps({
            'hostname': hostname,
            'folder': checkmk_default_folder,
            'attributes': {
                'tag_location': checkmk_default_location,
                'labels': hostlabels
                }
            })}

    logging.debug('-- adding host %s', hostname)
    r = requests.post("%s?action=add_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)
    logging.debug('-- got resp code = %d' % r.status_code)
    logging.debug('-- got resp text = %s' % r.text)
    r_json = json.loads(r.text)

    # Successful add_host gives response of {"result": null, "result_code": 0}
    if r_json['result_code'] == 0 and r_json['result'] is None:
        logging.info('added host %s successfully', hostname)
    else:
        logging.warn('failed to add host %s', r_json['result'])


def add_label_to_existing(hostname, new_labels):
    """ Add labels to existing host in checkmk """

    logging.debug('going to add labels %s to existing host %s' % (new_labels, hostname))

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']
    checkmk_puppetdb_label = config['checkmk_puppetdb_label']

    # Save the attributes, save the ~world~ existing labels
    req_params = { 'action': 'get_host',
        '_username': config['checkmk_api_username'],
        '_secret': config['checkmk_api_secret'],
        'hostname': hostname,
        'output_format': 'json' }
    r = requests.post(checkmk_api_url, req_params)

    existing_labels = {}
    try:
        existing_labels.update(r.json()['result']['attributes']['labels'])
    except:
        pass

    # add new labels to existing labels and ensure from_puppetdb label present
    existing_labels.update(new_labels)
    existing_labels.update({ 'from_puppetdb': checkmk_puppetdb_label })

    payload = {'request': json.dumps({
        'hostname': hostname,
        'attributes': {
            'labels': existing_labels
            }
        })}

    logging.debug('-- adding labels %s to host %s' % (existing_labels, hostname))
    r = requests.post("%s?action=edit_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)
    logging.debug('-- got resp code = %d' % r.status_code)
    logging.debug('-- got resp text = %s' % r.text)
    r_json = json.loads(r.text)

    # Successful edit_host gives response of {"result": null, "result_code": 0}
    if r_json['result_code'] == 0 and r_json['result'] is None:
        logging.info('added labels %s to %s successfully' % (existing_labels, hostname))
    else:
        logging.warn('failed to add labels %s to host %s' % (r_json['result'], hostname))


def del_host_from_checkmk(hostname):
    """ Delete host from checkmk """

    logging.debug('going to delete host %s', hostname)

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']

    payload = {'request': json.dumps({
        'hostname': hostname
        })}

    logging.debug('-- deleting host %s', hostname)
    r = requests.post("%s?action=delete_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)
    logging.debug('-- got resp code = %d' % r.status_code)
    logging.debug('-- got resp text = %s' % r.text)
    r_json = json.loads(r.text)

    # Successful delete_host gives response of {"result": null, "result_code": 0}
    if r_json['result_code'] == 0 and r_json['result'] is None:
        logging.info('deleted host %s successfully', hostname)
    else:
        logging.warn('failed to delete host %s', r_json['result'])



def main():

    logging.info('puppetdb-to-checkmk started')

    exclude_hosts = config.get('exclude_hosts', list())
    require_tag = config.get('require_tag', None)
    checkmk_puppetdb_label = config['checkmk_puppetdb_label']

    hosts_puppetdb = get_all_hosts_puppetdb()
    hosts_checkmk = get_all_hosts_checkmk()

    # Find hosts in puppetdb that are not in checkmk and not excluded,
    # adding hosts and from_puppetdb label as necessary
    hosts_missing_from_checkmk = []
    hosts_in_checkmk_with_label = []
    hosts_in_checkmk_without_label = []
    for host in hosts_puppetdb:
        # Consider host if not purposely excluded
        if host not in exclude_hosts:
            # If host is not already in checkmk
            if host not in hosts_checkmk:
                logging.warn('%s missing from checkmk', host)
                hosts_missing_from_checkmk.append(host)
                add_host_to_checkmk(host, hosts_puppetdb[host])
            else:
                logging.debug('%s present in checkmk', host)
                # Build minimal list of desired labels from puppetdb
                desired_labels = hosts_puppetdb[host]
                desired_labels.update({ 'from_puppetdb': checkmk_puppetdb_label })

                # Check if all desired labels are present in checkmk
                # and update if necessary
                missing_labels = {}
                for label in desired_labels:
                    if label not in hosts_checkmk[host]:
                        missing_labels[label] = desired_labels[label]

                if missing_labels:
                    logging.warn('existing host %s with missing labels %s' % (host, missing_labels))
                    hosts_in_checkmk_without_label.append(host)
                    add_label_to_existing(host, missing_labels)
                else:
                    logging.debug('existing host %s with correct labels %s' % (host, hosts_checkmk[host]))
                    hosts_in_checkmk_with_label.append(host)


    # Remove hosts from checkmk that are no longer in puppetdb or are excluded
    # Only consider hosts added by this tool with the same checkmk_puppetdb_label
    hosts_extra_in_checkmk = []
    for host in hosts_checkmk:
        if host not in hosts_puppetdb or host in exclude_hosts:
            logging.debug('host %s not in puppetdb or excluded' % host)
            # hosts_checkmk[host] will be true if from_puppetdb label present
            if hosts_checkmk[host]:
                hosts_extra_in_checkmk.append(host)
                if hosts_checkmk[host]['from_puppetdb'] == checkmk_puppetdb_label:
                    logging.debug('host %s has puppetdb_label from this instance, deleting' % host)
                    del_host_from_checkmk(host)
                else:
                    logging.debug('host %s has puppetdb_label but not from this instance' % host)
            else:
                logging.debug('host %s missing correct puppetdb_label, not deleting' % host)


    logging.info('%d hosts missing from checkmk', len(hosts_missing_from_checkmk))
    logging.info('%d hosts in checkmk with correct labels', len(hosts_in_checkmk_with_label))
    logging.info('%d hosts in checkmk with missing labels', len(hosts_in_checkmk_without_label))
    logging.info('%d extra hosts in checkmk', len(hosts_extra_in_checkmk))

    logging.info('puppetdb-to-checkmk ended')



if __name__ == "__main__":
    # Run script as main
    main()
