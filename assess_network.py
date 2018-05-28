import boto3
import json
import click
import jmespath
import time

# Updates needed- IPV6, an IP range that includes port 22
# Also add fix in case requested IP range is already in there
@click.command()
@click.option('--access', help='AWS Access Key. Otherwise will use the standard credentials path for the AWS CLI.')
@click.option('--secret', help='AWS Secret Key')
@click.option('--profile', help='If you have multiple credential profiles, use this option to specify one.')
@click.option('--region', help='Specify a single region to assess. By default all regions are assessed')
def assess_groups(region, access, secret, profile):
    global session
    if access:
        click.echo('Access Key specified')
        if not secret:
            click.echo('Secret key not specified. A secret key must be provided when the command line access key option is provided.')
        else:
            click.echo('Establishing AWS session using the provided access key...')
            try:
                session = boto3.session.Session(aws_access_key_id=access, aws_secret_access_key=secret)
            except:
                click.echo('Error establishing AWS connection. Likely bad credentials provided.')
                sys.exit()
    elif profile:
        click.echo('Establishing AWS session using the profile- ' + profile)
        try:
            session = boto3.session.Session(profile_name=profile)
        except:
            click.echo('Error establishing AWS connection. Likely bad credentials provided.')
            sys.exit()
    else:
        click.echo('Establishing AWS session using default path credentials...')
        try:
            session = boto3.session.Session()
        except:
            click.echo('Error establishing AWS connection. Likely bad credentials provided.')
            sys.exit()

    region_list = session.get_available_regions('ec2')
    network_map = {}
    flat_groups_list = {}
    group_total = 0
    instances_total = 0
    flat_group_total = 0
    for region in region_list:
        network_map[region] = {}
        ec2 = session.client('ec2', region_name=region)
        match_groups = []
        group_count = 0
        instance_count = 0
        secgroups = ec2.describe_security_groups(Filters=[
            {'Name': 'ip-permission.cidr', 'Values': ['0.0.0.0/0'] }
        ]
        )
        all_groups_paginator = ec2.get_paginator('describe_security_groups')
        all_groups = all_groups_paginator.paginate()
        for curgroup in secgroups['SecurityGroups']:
            groupid = curgroup['GroupId']
            group_total += 1
            group_count += 1
            network_map[region][groupid] = {}
            network_map[region][groupid]['Ports'] = []
            for permission in curgroup['IpPermissions']:
                if ('FromPort' in permission) or (permission['IpProtocol'] == "-1"):
                    for cidr in permission['IpRanges']:
                        if cidr['CidrIp'] == '0.0.0.0/0':
                            if permission['IpProtocol'] == "-1":
                                network_map[region][groupid]['Ports'].append('Any')
                            else:
                                network_map[region][groupid]['Ports'].append(permission['FromPort'])
                            match_groups.append(curgroup)
                            # the next block should be removed once we migrate to more-efficient collection of resources
                            instancelist = ec2.describe_instances(Filters=[
                                    {
                                        'Name': 'network-interface.group-id',
                                                'Values': [
                                                    groupid
                                                ]

                                    },
                                ])
                            network_map[region][groupid]['Instances'] = {}
                            if instancelist['Reservations'] != []:
                                for reservation in instancelist['Reservations']:
                                    for instance in reservation['Instances']:
                                        network_map[region][groupid]['Instances']['Instance ID'] = instance['InstanceId']
                                        instances_total += 1
                                        instance_count += 1
                                        network_map[region][groupid]['Instances']['Other Groups'] = []
                                        for interface in instance['NetworkInterfaces']:
                                            for group in interface['Groups']:
                                                curgroup2 = group['GroupId']
                                                if curgroup2 != groupid:
                                                    jmes_query = "SecurityGroups[?(GroupId == '" + curgroup2 + "')].IpPermissions"
                                                    rules = all_groups.search(jmes_query)
                                                    rule_list = []
                                                    for rule in rules:
                                                        if rule != []:
                                                            rule_list.append(rule)
                                                    network_map[region][groupid]['Instances']['Other Groups'].append({'Group ID': curgroup['GroupId'], 'Rules': rule_list})
            network_map[region][groupid]['Connected Groups'] = []
            # TODO update this to use JMESPath and allgroups, but in a hurry now and don;t want to take the time to do it the right way
            othergroups = ec2.describe_security_groups(Filters=[
                {'Name': 'ip-permission.group-id', 'Values': [groupid]}
            ]
            )
            time.sleep(1)
            for group in othergroups['SecurityGroups']:
                data = {}
                data['Group ID'] = group['GroupId']
                portlist = []
                for permission in group['IpPermissions']:
                    for usergroup in permission['UserIdGroupPairs']:
                        if usergroup['GroupId'] == groupid:
                            if ('FromPort' in permission):
                                if permission['FromPort'] == -1:
                                    portlist.append('Any')
                                else:
                                    portlist.append(permission['FromPort'])
                            elif (permission['IpProtocol'] == "-1"):
                                portlist.append('Any')

                data['Open Ports'] = portlist
                network_map[region][groupid]['Connected Groups'].append(data)
        # Identify "flat" security groups
        flat_groups_list[region] = {}
        for page in all_groups:
            for curgroup in page['SecurityGroups']:
                for permission in curgroup['IpPermissions']:
                    if ('FromPort' in permission) or (permission['IpProtocol'] == "-1"):
                        for usergroup in permission['UserIdGroupPairs']:
                            if usergroup['GroupId'] == curgroup['GroupId']:
                                flat_groups_list[region][curgroup['GroupId']] = []
                                flat_group_total += 1
                                if ('FromPort' in permission):
                                    if permission['FromPort'] == -1:
                                        flat_groups_list[region][curgroup['GroupId']].append('Any')
                                    else:
                                        flat_groups_list[region][curgroup['GroupId']].append(permission['FromPort'])
                                elif permission['IpProtocol'] == "-1":
                                    flat_groups_list[region][curgroup['GroupId']].append('Any')
        # need to fix the data structure here... out fo time for now
        # network_map[region]['RegionGroupTotal'] = str(group_count)
        # network_map[region]['RegionInstanceTotal'] = str(instance_count)
    report = open("NetworkReport.md", "w")
    report.write('# Network Exposure Report\n')
    report.write('\n')
    report.write('This report shows all Security Groups and Instances exposed to 0.0.0.0/0, and any additional internal connections\n')
    report.write('We found **' + str(group_total) + ' exposed security groups** across all regions, containing **'+ str(instances_total) + ' instances**\n')
    for key, value in network_map.items():
        if value != {}:
            report.write('## Internet exposed Security Groups for ' + key + '\n')
            # fix this once data structure fixed
            # report.write('Exposed security groups: ' + value['RegionGroupTotal'] + '\n')
            # report.write('Exposed instances: ' + value['RegionInstanceTotal'] + '\n')
            for key1, value in value.items():
                report.write('\n')
                report.write('### Security Group ID: ' + key1 + '\n')
                report.write('* Ports open to 0.0.0.0/0: \n')
                for port in value['Ports']:
                    report.write('    * ' + str(port) + '\n')
                report.write('* Instances exposed in the security group: \n')

                if value['Instances'] == {}:
                    report.write('    * _No instances in the security group_\n')
                else:
                    report.write('    * Instance ID: ' + value['Instances']['Instance ID'] + '\n')
                    report.write('      * Other security groups this instance is in: \n')
                    if value['Instances']['Other Groups'] == []:
                        report.write('        * _Instance not in any other security groups_\n')
                    else:
                        for group in value['Instances']['Other Groups']:
                            report.write('        * Security Group ID: ' + group['Group ID'] + '\n')
                            report.write("            * JSON of the security group's rules:\n")
                            report.write('                * ' + json.dumps(group['Rules']) + '\n')
                if value['Connected Groups'] == []:
                    report.write('    * _No other security groups directly trust this exposed group_\n')
                else:
                    report.write('* Other security groups that trust this group: \n')
                    for group in value['Connected Groups']:
                        report.write('    * Security Group ID: ' + group['Group ID'] + '\n')
                        report.write('    * Open Ports:\n')
                        for port in group['Open Ports']:
                            report.write('        * ' + str(port) + '\n')
    report.write('# Flat Security Groups\n')
    report.write('We found **' + str(flat_group_total) + ' security groups allowing access to peers in the same group.\n')
    for key, value in flat_groups_list.items():
        if value != {}:
            report.write('## Flat Security Groups for ' + key + '\n')
            for key, value in value.items():
                report.write('\n')
                report.write('### Security Group ID: ' + key + '\n')
                report.write('* Ports open to peers in the same group:\n')
                for port in value:
                    report.write('    * ' + str(port) + '\n')
    report.close()




if __name__ == "__main__":
    assess_groups()