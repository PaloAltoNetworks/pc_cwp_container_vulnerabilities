""" Get Vulnerabilities in Containers (Deployed Images) """
revision = "20230109-1"

#Authored by Greg Wilkerson 01/06/2023
#Authored by Adam Hamilton-Sutherland 01/06/2023

import json
import csv
from datetime import datetime, timedelta

# pylint: disable=import-error
from prismacloud.api import pc_api, pc_utility

#Debugging Code - comment out for Prod
# class File_Dump:
#     def json(json_data, f_name):
#         with open(f_name, 'w') as outfile:
#             json.dump(json_data, outfile)
    
#     def text(data, f_name):
#         with open(f_name, 'w') as outfile:
#             outfile.write(data)

# f_dump = File_Dump

# --Configuration-- #

DEFAULT_FILE_NAME = 'container_vulns.csv'

parser = pc_utility.get_arg_parser()
parser.add_argument(
    '-f',
    '--filename',
    type=str,
    default=DEFAULT_FILE_NAME,
    help="(Optional) - Export to the given file name. (Default %s)" % DEFAULT_FILE_NAME
)
parser.add_argument(
    '-i'
    '--includeID',
    type=bool,
    default=False,
    help="(Optional) - Include ContainerIDs with Container Names as ContainerName (ContainerID),... (Default FALSE)"
)
args = parser.parse_args()

# --Initialize-- #

settings = pc_utility.get_settings(args)
pc_api.configure(settings)
pc_api.validate_api_compute()

# --Helpers-- #

def datetime_or_empty(datetime_string):
    if int(datetime_string) == 0:
        return ""
    return datetime.utcfromtimestamp(int(datetime_string)).strftime('%Y-%m-%d %H:%M:%S')

def strip_csv_breaking_characters(original_string):
    return str(original_string).replace("\"","|").replace("\'","|")

# --Main-- #
print('Revision: ' + revision, end='')
print()

start_time = datetime.now()
print('Starting Process at: '+ start_time.strftime('%Y-%m-%d %H:%M:%S'), end='')
print()


print('Outputting to: '+ args.filename, end='')
print()

print('Testing Compute API Access ...', end='')
intelligence = pc_api.statuses_intelligence()
test_complete_time = datetime.now()
test_elapsed_time = test_complete_time - start_time 
print('Done. (Elapsed Time: ' + str(test_elapsed_time) + ')', end='')
print()


#/api/cloud/cwpp/hosts#operation/get-hosts
print('Getting Hosts (please wait) ...', end='')
hosts = pc_api.hosts_list_read()
host_complete_time = datetime.now()
host_elapsed_time = host_complete_time - test_complete_time 
print('Done. (Elapsed Time: ' + str(host_elapsed_time) + ')', end='')
print()
#Debug
# f_dump.json(hosts[0], "hosts.json")

# /api/cloud/cwpp/images#operation/get-images
print('Getting Deployed Images (please wait) ...', end='')
images = pc_api.images_list_read(query_params={'filterBaseImage': 'true'})
image_complete_time = datetime.now()
image_elapsed_time = image_complete_time - host_complete_time
print('Done. (Elapsed Time: ' + str(image_elapsed_time) + ')', end='')
print()
#Debug
# f_dump.json(images[1], 'images.json')

# /api/cloud/cwpp/containers#operation/get-containers
print('Getting Containers (please wait) ...', end='')
containers_list = pc_api.containers_list_read()
container_complete_time = datetime.now()
container_elapsed_time = container_complete_time - image_complete_time
print('Done. (Elapsed Time: ' + str(container_elapsed_time) + ')', end='')
print()
#Debug
# f_dump.json(containers_list[:5], 'conts.json')

print('Writing Results to File (please wait) ...', end='')

#Defining the CSV Line Object class where all data for each line will be stored. There will be a Line object for each line in the CSV
class CSV_Line:
    registry = ""
    repository = ""
    tag = ""
    image_id = ""
    distro = ""
    hostname = ""
    layer = "TODO_LAYER"
    cve = ""
    compliance_id = ""
    image_type = ""
    severity = ""
    packages = ""
    source_package = "TODO_SOURCE_PACKAGE"
    package_version = ""
    package_license = ""
    cvss = ""
    fix_status = ""
    fix_date = ""
    grace_days = "TODO_GRACEPERIODDAYS"
    risk_factors ="TODO_RISK_FACTORS"
    vuln_tags = "TODO_TAGS"
    description = ""
    cause = ""
    
    custom_labels = "TODO_CUSTOM_LABELS"
    published = ""
    discovered = ""
    binaries = "TODO_BINARIES"
    clusters = ""
    namespaces = ""
    collections = "TODO_COLLECTIONS"
    digest = "TODO_DIGEST"
    vuln_link = ""
    apps = "TODO_APPS"
    package_path = ""

    containers_str_list = ""

#Function used when writing lines of the CSV. This creates a single CSV string that can be dumped to a file.
def csv_line_dump(l: CSV_Line) -> str:
    out_str = ""
    out_str += l.registry + ','
    out_str += l.repository + ','
    out_str += l.tag + ','
    out_str += l.image_id + ','
    out_str += l.distro + ','
    out_str += l.hostname + ','
    out_str += l.layer + ','
    out_str += l.cve + ','
    out_str += str(l.compliance_id) + ','
    out_str += str(l.image_type) + ','
    out_str += str(l.severity) + ','
    out_str += str(l.packages) + ','
    out_str += str(l.source_package)  + ','
    out_str += str(l.package_version)  + ','
    out_str += str(l.package_license)  + ','
    out_str += str(l.cvss)  + ','
    out_str += str(l.fix_status) + ','
    out_str += str(l.fix_date) + ','
    out_str += str(l.grace_days) + ','
    out_str += str(l.risk_factors) + ','
    out_str += str(l.vuln_tags) + ','
    out_str += '"' + str(l.description) + '",'
    out_str += '"' + str(l.cause) + '",'
    out_str += '"' + str(l.containers_str_list[:-1]) + '",'
    out_str += str(l.custom_labels) + ','
    out_str += str(l.published) + ','
    out_str += str(l.discovered) + ','
    out_str += str(l.binaries) + ','
    out_str += str(l.clusters)  + ','
    out_str += str(l.namespaces) + ','
    out_str += str(l.collections) + ','
    out_str += str(l.digest) + ','
    out_str += str(l.vuln_link) + ','
    out_str += str(l.apps) + ','
    out_str += str(l.package_path)

    return out_str

#Creating helper data sets
hostname_dict = {}
hosts_id_dict = {}
for host in hosts:
    hosts_id = host['_id']
    hostname = host['hostname']
    hosts_id_dict[hosts_id] = host
    hostname_dict[hostname] = host
images_id_dict = {}
for image in images:
    image_id = image['_id']
    images_id_dict[image_id] = image


#Core data set, the list of all line objects.
lines_objects = [] #Holds all data that will be turned into CSVs

#Holds lists of containers running for a unique host. Based on combining Registry/Repository/Image/Hostname/Namespace
# hostname_to_container_id_list_string = {}
unique_id_to_containers_list_string = {}

#Ensure each line is unique based on a combination of values
unique_lines_set = set()

#The main loop for creating the CSV. For each container, get all its CVEs and the hostname it belongs too.
for container in containers_list:
    #Initializing values used to ensure each CSV Line Object is unique based on a combination of these values.
    reg = ""#
    repo = ""#
    tag = "" #
    image_id = ""#
    distro = ""#
    cluster = ""#
    namespace = ""#
    host = "" #
    cve = ""#
    image_type = ""#

    if 'imageID' in container['info']:
        image_id = container['info']['imageID']
        host = container['hostname']
        cluster = container['info'].get('cluster', "")
        namespace = container['info'].get('namespace', "")
    
    if image_id in images_id_dict:
        image = images_id_dict[image_id]
        reg = image['repoTag']['registry']
        repo = image['repoTag']['repo']
        tag = image['repoTag']['tag']
        distro = image['distro']
        image_type = image['type']

        packages_dictionary = {}
        if 'packages' in image:
            for package in image['packages']:
                if 'pkgs' in package:
                    for pkg in package['pkgs']:
                        if 'name' in pkg and 'version' in pkg:
                            packages_dictionary[pkg['name'] + pkg['version']] = pkg

        
        #Main logic for building out lines of the CSV based on vulnerabilities found for each image. Only images with vulnerabilities will be processed
        if not image.get('vulnerabilities'):
            continue#skips the rest of this loop
        
        #Each line of output is generated based on a vulnerability. Ideally we will have one line of output in the CSV for each CVE found in the environnement. 
        for vuln in image.get('vulnerabilities', []):
            cve = vuln['cve']
            
            #Defining identifiers to combine to create unique value strings. Used to organize containers into their Hosts and ensure we dont output duplicate CSV lines
            line_id = reg + repo + image_id + cluster + namespace + host + cve #used for deciding when to output a line
            unique_id = reg + repo + image_id + host + namespace #Used for getting containers for a given Registry/Repository/Image/Hostname/Namespace
            
            #For each unique hostname, create/add a list of containers that belong to that unique hostname.
            if unique_id not in unique_id_to_containers_list_string:
                if args.includeID:
                    unique_id_to_containers_list_string[unique_id] = container['info']['name'] + '(' + container['_id'] + ')' + ','
                else:
                    unique_id_to_containers_list_string[unique_id] = container['info']['name'] + ','
            else:
                if args.includeID:
                    value_to_add = container['info']['name'] + '(' + container['_id'] + ')' + ','
                else:
                    value_to_add = container['info']['name'] + ','
                
                if value_to_add not in unique_id_to_containers_list_string[unique_id]:
                    unique_id_to_containers_list_string[unique_id] = unique_id_to_containers_list_string[unique_id] + value_to_add

            #Extracting values from the JSON API Response
            description = strip_csv_breaking_characters(vuln['description'])
            published_date = datetime_or_empty(vuln['published'])
            fix_date       = datetime_or_empty(vuln['fixDate'])
            package_version = vuln['packageVersion']
            package_name = vuln['packageName']

            #Package information does not always exist so it has to be constructed conditionally
            package_path = ""
            package_license = ""
            package_key = package_name + package_version
            if package_key in packages_dictionary:
                package_info    = packages_dictionary[package_key]
                package_path    = package_info.get('path', "")
                package_license = package_info.get('license', "")    
            
            #Line_id is created from combining values that make a line unique. This allows us to ensure we do not have duplicate lines in the output.
            if line_id not in unique_lines_set:
                #add to the set of unquie lines
                unique_lines_set.add(line_id)

                #Create a line object that contains all values that will be output into the CSV fields.
                #Create line object and set values
                l = CSV_Line()

                #These values have already been extracted
                l.registry = reg
                l.repository = repo
                l.tag = tag
                l.image_id = image_id
                l.distro = distro
                l.hostname = host
                l.cve = cve
                
                #Extract these values from the JSON data, defaulting to null if the data does not exist.
                l.compliance_id = vuln.get('templates', "null")
                l.image_type = image_type
                l.severity = vuln.get('severity', "null")
                l.packages = vuln.get('packageName', "null")
                l.package_version = vuln.get('packageVersion', "null")
                l.package_license = package_license
                l.cvss = vuln.get('cvss', "null")
                l.fix_status = vuln.get('status, "null')
                l.fix_date = fix_date
                l.description = description
                l.cause = vuln.get('cause', "null")
                l.published = published_date
                l.discovered = vuln.get('discovered', "null")
                l.clusters = cluster
                l.namespaces = namespace
                l.vuln_link = vuln.get('link', 'null')
                l.package_path = package_path      

                #add the line object to the list of line objects that will be looped over to create the CSV output
                lines_objects.append(l)      
                

#Loop over all line_objects for writing to file
#Open output file for writing using either the default name or the file name included as a command line argument.
with open(args.filename, 'w') as outfile:
    outfile.write("Registry,Repository,Tag,Id,Distro,Hosts,Layer,CVE ID,Compliance ID,Type,Severity,Packages,Source Package,Package Version,Package License,CVSS,Fix Status,Fix Date,Grace Days,Risk Factors,Vulnerability Tags,Description,Cause,\"Containers[Name(ID),Name(ID)...]\",Custom Labels,Published,Discovered,Binaries,Clusters,Namespaces,Collections,Digest,Vulnerability Link,Apps,Package Path\n")
    
    #Debugging output for the hostname to container mapping.
    # f_dump.json(unique_id_to_containers_list_string, 'unique_strings_dict.json')

    #Loop over all of the line objects that have been added so the values can be extracted and output to the CSV file
    for line_obj in lines_objects:
        #This script takes only one pass at the entire data set so the complete list of containers on a host is not available at the time the Line object
        # is created. Therefore the container list for each host comes from a seperate data structure that we access now, since at this point, the entire dataset has been processed. 
        unique_id = line_obj.registry + line_obj.repository + line_obj.image_id + line_obj.hostname + line_obj.namespaces 
        containers = unique_id_to_containers_list_string[unique_id]

        line_obj.containers_str_list = containers

        #Now that we have updated the line object with the list of containers, we can write the line to the output file.
        outfile.write(csv_line_dump(line_obj) + '\n')


#Logging total runtime and date this CSV was created.
write_elapsed_time = datetime.now() - container_complete_time
print('Done. (Elapsed Time: ' + str(write_elapsed_time) + ')', end='')
print()

total_elapsed_time = datetime.now() - start_time

print('Complete at ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' (Total Time: ' + str(total_elapsed_time) + ')', end='')
print()