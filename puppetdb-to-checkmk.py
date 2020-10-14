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
import pprint
import requests
import socket
import yaml


parser = argparse.ArgumentParser()
parser.add_argument('--config', type=argparse.FileType('r'),
                    default='config.yaml', help='YAML config (default config.yaml)')
args = parser.parse_args()
config = yaml.safe_load(args.config)


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
        for tag in res['tags']:
            if tag.startswith('roles::'):
                host_role = tag[7:]
        hosts[hostname] = { 'puppet_role': host_role }

    return hosts


def add_host_to_checkmk(hostname, hostlabels):
    """ Add host to checkmk with any hostlabels from puppetdb, adding label of
        from_puppetdb=true to help indicate host was added by this script
    """

    print("ADDING host=%s with hostlabels=%s" % (hostname, hostlabels))

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']

    hostlabels['from_puppetdb'] = 'true'

    # Determine if host is dual stacked v4/v6 and include ip-v4v6
    # address_family if so, else leave address_family off to use default
    try:
        d = dns.resolver.resolve(hostname, 'AAAA')
        print("dual stacked, adding ip-v4v6")
        payload = {'request': json.dumps({
            'hostname': hostname,
            'folder': 'Servers/SHOR',
            'attributes': {
                'tag_location': 'location_shor',
                'tag_address_family': 'ip-v4v6',
                'labels': hostlabels
                }
            })}
    except Exception as e:
        print("not dual stack")
        payload = {'request': json.dumps({
            'hostname': hostname,
            'folder': 'Servers/SHOR',
            'attributes': {
                'tag_location': 'location_shor',
                'labels': hostlabels
                }
            })}


    print("-- adding host %s" % hostname)
    r = requests.post("%s?action=add_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)
    print("addhost resp code=", r.status_code)
    print("addhost resp=", r.text)
    r_json = json.loads(r.text)

    # Successful add_host gives response of {"result": null, "result_code": 0}
    if r_json['result_code'] == 0 and r_json['result'] is None:
        print("Added host successfully: %s" % hostname)
    else:
        print("Failed to add host: %s" % r_json['result'])


def add_label_to_existing(hostname, new_labels):
    """ Add labels to existing host in checkmk """

    print("Adding labels to existing:", hostname, new_labels)

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

    existing_labels = {}
    try:
        existing_labels.update(r.json()['result']['attributes']['labels'])
    except:
        pass

    # add new labels to existing labels and ensure from_puppetdb:true
    existing_labels.update(new_labels)
    existing_labels.update({ 'from_puppetdb': 'true' })

    payload = {'request': json.dumps({
        'hostname': hostname,
        'attributes': {
            'labels': existing_labels
            }
        })}

    r = requests.post("%s?action=edit_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)


def del_host_from_checkmk(hostname):
    """ Delete host from checkmk """

    checkmk_api_url = config['checkmk_api_url']
    checkmk_api_username = config['checkmk_api_username']
    checkmk_api_secret = config['checkmk_api_secret']

    payload = {'request': json.dumps({
        'hostname': hostname
        })}

    r = requests.post("%s?action=delete_host&_username=%s&_secret=%s" % (checkmk_api_url, checkmk_api_username, checkmk_api_secret), data=payload)
    print("delhost resp code=", r.status_code)
    print("delhost resp=", r.text)
    r_json = json.loads(r.text)

    # Successful delete_host gives response of {"result": null, "result_code": 0}
    if r_json['result_code'] == 0 and r_json['result'] is None:
        print("Deleted host successfully: %s" % hostname)
    else:
        print("Failed to delete host: %s" % r_json['result'])



def main():

    exclude_hosts = config.get('exclude_hosts', list())
    require_tag = config.get('require_tag', None)

    hosts_puppetdb = get_all_hosts_puppetdb()
    hosts_checkmk = get_all_hosts_checkmk()

    print("puppetdb=%d\ncheckmk=%d\n" % (len(hosts_puppetdb), len(hosts_checkmk)))

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
                print("\nMissing from checkmk: %s" % host)
                hosts_missing_from_checkmk.append(host)
                add_host_to_checkmk(host, hosts_puppetdb[host])
            else:
                print("\nPresent in checkmk: %s" % host)
                # Build minimal list of desired labels from puppetdb
                desired_labels = hosts_puppetdb[host]
                desired_labels.update({ 'from_puppetdb': 'true' })

                # Check if all desired labels are present in checkmk
                # and update if necessary
                missing_labels = {}
                for label in desired_labels:
                    if label not in hosts_checkmk[host]:
                        missing_labels[label] = desired_labels[label]

                if missing_labels:
                    print("  Existing host with missing labels: %s, %s" % (host, hosts_checkmk[host]))
                    print("    Missing: %s" % missing_labels)
                    hosts_in_checkmk_without_label.append(host)
                    add_label_to_existing(host, missing_labels)
                else:
                    print("  Existing host with correct labels: %s, %s" % (host, hosts_checkmk[host]))
                    hosts_in_checkmk_with_label.append(host)


    # Remove hosts from checkmk that are no longer in puppetdb or are excluded
    hosts_extra_in_checkmk = []
    for host in hosts_checkmk:
        if host not in hosts_puppetdb or host in exclude_hosts:
            # hosts_checkmk[host] will be true if from_puppetdb label present
            if hosts_checkmk[host]:
                hosts_extra_in_checkmk.append(host)
                print("Removing host from checkmk: %s" % host)
                del_host_from_checkmk(host)


    print("Hosts missing from CheckMK: %d" % len(hosts_missing_from_checkmk))
    print("Hosts in CheckMK with label: %d" % len(hosts_in_checkmk_with_label))
    print("Hosts in CheckMK without label: %d" % len(hosts_in_checkmk_without_label))
    print("Extra hosts in CheckMK to delete: %d" % len(hosts_extra_in_checkmk))


if __name__ == "__main__":
    # Run script as main
    main()
