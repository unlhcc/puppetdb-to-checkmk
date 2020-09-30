#!/usr/bin/env python
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

"""
Sync hosts from puppetdb to checkmk using API

    - get list from puppetdb and checkmk
    - add missing hosts to checkmk, add magic puppetdb label if necessary
    - delete extras (only if magic puppetdb label present) from checkmk
    - profit!
"""

import argparse
import json
import requests
import yaml
import pprint


parser = argparse.ArgumentParser()
parser.add_argument('config', type=argparse.FileType('r'), help='YAML config')
args = parser.parse_args()
config = yaml.safe_load(args.config)



def get_all_hosts_checkmk():
    """ Get existing hosts in checkmk and return dict
        containing { hostname, whether host was from puppetdb } """

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
        print("\n  attrs: ", host[0], host[1]['attributes'])
        if 'from_puppetdb' in hostlabels:
            if hostlabels['from_puppetdb'] == 'true':
                hosts[hostname] = True
        else:
            hosts[hostname] = False

    return hosts


def get_all_hosts_puppetdb():
    """ Get existing hosts in puppetdb and return list of hostnames """

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

    hosts = []
    for res in r.json():
        hosts.append(res['certname'])
    return hosts


def add_host_to_checkmk(hostname):
    """ Add host to checkmk with explicit label of from_puppetdb=true
        to help indicate host was added by this script
    """

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']

    payload = {'request': json.dumps({
        'hostname': hostname,
        'folder': 'Servers/SHOR',
        'attributes': {
            'tag_location': 'location_shor',
            'labels': {
                'from_puppetdb': 'true'
                }
            }
        })}

    r = requests.post("%s?action=add_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)
    print("addhost resp code=", r.status_code)
    print("addhost resp=", r.text)


def add_label_to_existing(hostname):
    """ Add from_puppetdb=true label to existing host in checkmk """

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']

    # Save the attributes, save the ~world~ existing labels
    req_params = { 'action': 'get_host',
        '_username': config['checkmk_api_username'],
        '_secret': config['checkmk_api_secret'],
        'hostname': hostname,
        'output_format': 'json' }
    r = requests.post(checkmk_api_url, req_params)
    print("host attrs: ", r.json()['result']['attributes'])

    host_labels = {}
    try:
        host_labels = r.json()['result']['attributes']['labels']
        host_labels.update({ 'from_puppetdb': 'true' })
    except:
        host_labels.update({ 'from_puppetdb': 'true' })

    payload = {'request': json.dumps({
        'hostname': hostname,
        'attributes': {
            'labels': host_labels
            }
        })}

    r = requests.post("%s?action=edit_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)


def del_host_from_checkmk(hostname):
    pass


def main():

    exclude_hosts = config.get('exclude_hosts', list())
    require_tag = config.get('require_tag', None)

    hosts_puppetdb = get_all_hosts_puppetdb()
    hosts_checkmk = get_all_hosts_checkmk()

    print("puppetdb=%d\ncheckmk=%d\n" % (len(hosts_puppetdb), len(hosts_checkmk)))

    # find hosts in puppetdb that are not in checkmk
    # add hosts or label as necessary
    hosts_missing_from_checkmk = []
    hosts_in_checkmk_without_label = []
    for host in hosts_puppetdb:
        if host not in hosts_checkmk:
            #print("Missing host: %s" % host)
            hosts_missing_from_checkmk.append(host)
            #add_host_to_checkmk(host)
        else:
            # host is in checkmk already
            if hosts_checkmk[host]:
                print("Existing host with correct label: %s, %s" % (host, hosts_checkmk[host]))
            else:
                print("Existing host with missing label: %s, %s" % (host, hosts_checkmk[host]))
                add_label_to_existing(host)


if __name__ == "__main__":
    # Run script as main
    main()
