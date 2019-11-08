"""
Copyright (c) 2018 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Chris McHenry"
__copyright__ = "Copyright (c) 2018 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

import pydot
import argparse
import json
from builtins import input
from tetpyclient import RestClient
import requests.packages.urllib3
from terminaltables import AsciiTable
import csv

API_ENDPOINT="{{TETRATION URL}}"
API_CREDS="{{PATH TO TETRATION API CREDS JSON}}"

def selectTetrationApps(endpoint,credentials):

    restclient = RestClient(endpoint,
                            credentials_file=credentials,
                            verify=False)

    requests.packages.urllib3.disable_warnings()
    resp = restclient.get('/openapi/v1/applications')

    if not resp:
        sys.exit("No data returned for Tetration Apps! HTTP {}".format(resp.status_code))

    app_table = []
    app_table.append(['Number','Name','Author','Primary'])
    print('\nApplications: ')
    for i,app in enumerate(resp.json()):
        app_table.append([i+1,app['name'],app['author'],app['primary']])
    print(AsciiTable(app_table).table)
    choice = input('\nSelect Tetration App: ')

    choice = choice.split(',')
    appIDs = []
    for app in choice:
        if '-' in app:
            for app in range(int(app.split('-')[0]),int(app.split('-')[1])+1):
                appIDs.append(resp.json()[int(app)-1]['id'])
        else:
            appIDs.append(resp.json()[int(app)-1]['id'])

    return appIDs

def main():
    """
    Main execution routine
    """
    parser = argparse.ArgumentParser(description='Tetration Policy to DOT')
    parser.add_argument('--maxlogfiles', type=int, default=10, help='Maximum number of log files (default is 10)')
    parser.add_argument('--debug', nargs='?',
                        choices=['verbose', 'warnings', 'critical'],
                        const='critical',
                        help='Enable debug messages.')
    parser.add_argument('--config', default=None, help='Configuration file')
    args = parser.parse_args()
    apps = []
    if args.config is None:
        print('%% No configuration file given - connecting directly to Tetration')
        try:
            restclient = RestClient(API_ENDPOINT,credentials_file=API_CREDS,verify=False)
            appIDs = selectTetrationApps(endpoint=API_ENDPOINT,credentials=API_CREDS)
            for appID in appIDs:
                print('Downloading app details for '+appID)
                apps.append(restclient.get('/openapi/v1/applications/%s/details'%appID).json())
        except:
            print('Error connecting to Tetration')
    else:
        # Load in the configuration
        try:
            with open(args.config) as config_file:
                apps.append(json.load(config_file))
        except IOError:
            print('%% Could not load configuration file')
            return
        except ValueError:
            print('Could not load improperly formatted configuration file')
            return

    protocols = {}
    try:
        with open('protocol-numbers-1.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                protocols[row['Decimal']]=row
    except IOError:
        print('%% Could not load protocols file')
        return
    except ValueError:
        print('Could not load improperly formatted protocols file')
        return

    showPorts = input('\nWould you like to include ports and protocols in the diagram? [Y,N]: ')

    if showPorts.upper() == 'Y':
        showPorts = True
    elif showPorts.upper() == 'N':
        showPorts = False
    else:
        print('Invalid input.')
        return

    for appDetails in apps:
        internal = 0
        external = 0
        clusters_subgraph=pydot.Subgraph('Clusters',label='Application Policy Groups',rank='"same"')
        filters_subgraph=pydot.Subgraph('Filters',label='External Policy Groups',rank='"same"')
        print('\nPreparing "%s"...'%appDetails['name'])
        if 'clusters' in appDetails.keys():
            for cluster in appDetails['clusters']:
                node_names = cluster['name'] + ':'
                for node in cluster['nodes']:
                    node_names = node_names + '\n' + node['name']
                clusters_subgraph.add_node(pydot.Node(cluster['id'],label=node_names,shape='rectangle',style='filled',fontcolor='white',fillcolor='royalblue4'))
                internal += 1
        if 'inventory_filters' in appDetails.keys():
            for invfilter in appDetails['inventory_filters']:
                if invfilter['name'] == appDetails['app_scope']['name']:
                    clusters_subgraph.add_node(pydot.Node(invfilter['id'],label='"'+invfilter['name']+'"',shape='rectangle',style='filled',fontcolor='white', fillcolor='orange2'))
                    internal += 1
                else:
                    filters_subgraph.add_node(pydot.Node(invfilter['id'],label='"'+invfilter['name']+'"',shape='rectangle',style='filled',fontcolor='white', fillcolor='orange2'))
                    external += 1

        if external > internal:
            rankdir='LR'
        else:
            rankdir='RL'
        graph = pydot.Dot(graph_type='digraph',name=appDetails['name'],label='Application Name: '+appDetails['name'],rankdir=rankdir)
        graph.add_subgraph(clusters_subgraph)
        graph.add_subgraph(filters_subgraph)
        
        if 'default_policies' in appDetails.keys():
            for policy in appDetails['default_policies']:
                pols=None
                if showPorts:
                    pols = {}
                    for rule in policy['l4_params']:
                        if 'port' in rule:
                            if rule['port'][0] == rule['port'][1]:
                                port = str(rule['port'][0])
                            else:
                                port = str(rule['port'][0]) + '-' + str(rule['port'][1])
                        else:
                            port = None

                        if port == None:
                            try:
                                pols[protocols[str(rule['proto'])]['Keyword']] = []
                            except:
                                pols['PROTO-'+str(rule['proto'])]=[]
                        elif protocols[str(rule['proto'])]['Keyword'] in pols.keys():
                            pols[protocols[str(rule['proto'])]['Keyword']].append(port)
                        else:
                            pols[protocols[str(rule['proto'])]['Keyword']] = [port]

                    policy_list = []
                    for key, val in pols.items():
                        if len(val)>0:
                            policy_list.append('{}={}'.format(key,', '.join(val)))
                        else:
                            policy_list.append(key)

                if pols:
                    graph.add_edge(pydot.Edge(policy['consumer_filter_id'],policy['provider_filter_id'],label='; '.join(policy_list)))
                else:
                    graph.add_edge(pydot.Edge(policy['consumer_filter_id'],policy['provider_filter_id']))

        if showPorts:                            
            f = open(appDetails['name'].replace('/','-')+'.dot','w')
        else:
            f = open(appDetails['name'].replace('/','-')+'-no-ports.dot','w')
        f.write(graph.to_string())

if __name__ == '__main__':
    main()
