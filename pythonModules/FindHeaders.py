from flask import Flask, render_template, request, jsonify
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from flask import Flask, render_template, request, redirect, url_for
import validators
import requests, re
from multiprocessing import Pool
import signal, threading
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import HTTPError, Timeout
import urllib3, datetime
import sqlite3
from sqlite3 import Error
import os, json, traceback, time
import hashlib
import concurrent.futures
import warnings
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime



allowRedirects = False
timeout_value = 5

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

from FindbasicDirectories import check_vulnerable_headers


# Get today's date
today = datetime.now()

def findSoftwareVersion(software, version):
    try:
        result = requests.get(f"https://endoflife.date/api/{software}.json").content
        result = json.loads(result)
        correctCycle = ''
        count = 0
        foundCount = 0

        for cycle in result:
            count +=1
            if version <= cycle["latest"]:
                correctCycle = cycle
                foundCount = count
        todayDate = (today.strftime("%Y-%m-%d"))
        eol = 'False'
        if str(correctCycle["eol"]) != 'False':
            print (f"\nUnsupported {software}")
            latest_version = result[0]["latest"]  # Store the latest version in a variable
            print(f"Latest version = {latest_version} Current version = {version}") 
            return ({"vulnerability":["End-of-Life-Software"], "colour": "red", "Current-version":version, "Latest-version": latest_version})
           
        elif version < correctCycle["latest"]:  
            print (f"\nOutdated {software}")
            latest_version = result[0]["latest"]  # Store the latest version in a variable
            print(f"Latest version = {latest_version} Current version = {version}")   
            return ({"vulnerability":["Outdated-Software"], "colour": "yellow", "Current-version":version, "Latest-version": latest_version})

        else:
            print (f"\n{software} Up to date!\n")
            latest_version = result[0]["latest"]
            return {"vulnerability": ["None"], "colour": "plain"}
    except:
        print (f"\nError with library {software}\n")
        return {"vulnerability": ["None"], "colour": "plain"}



def is_eol_software(software_name):
    # Define the EoL software list
    EoL_software = ["akeneo-pim","alibaba-dragonwell","almalinux","alpine","amazon-cdk","amazon-corretto","amazon-eks","amazon-glue","amazon-linux","amazon-neptune","amazon-rds-mysql","amazon-rds-postgresql","android","angular","angularjs","ansible","ansible-core","antix","apache","apache-activemq","apache-airflow","apache-camel","apache-cassandra","apache-groovy","apache-hadoop","apache-hop","apache-kafka","apache-spark","apache-struts","api-platform","apple-watch","arangodb","argo-cd","artifactory","aws-lambda","azul-zulu","azure-devops-server","azure-kubernetes-service","bazel","beats","bellsoft-liberica","blender","bootstrap","bun","cakephp","centos","centos-stream","centreon","cert-manager","cfengine","chef-infra-server","citrix-vad","ckeditor","clamav","cockroachdb","coldfusion","composer","confluence","consul","containerd","contao","cortex-xdr","cos","couchbase-server","craft-cms","dbt-core","debian","dependency-track","devuan","django","docker-engine","dotnet","dotnetfx","drupal","drush","eclipse-jetty","eclipse-temurin","elasticsearch","electron","elixir","emberjs","envoy","erlang","esxi","etcd","eurolinux","exim","fairphone","fedora","ffmpeg","filemaker","firefox","flux","fortios","freebsd","gerrit","gitlab","go","goaccess","godot","google-kubernetes-engine","google-nexus","gorilla","graalvm","gradle","grafana","grails","graylog","gstreamer","haproxy","hashicorp-vault","hbase","horizon","ibm-aix","ibm-i","ibm-semeru-runtime","icinga-web","intel-processors","internet-explorer","ionic","ios","ipad","ipados","iphone","isc-dhcp","istio","jekyll","jenkins","jhipster","jira-software","joomla","jquery","jreleaser","kde-plasma","keda","keycloak","kibana","kindle","kirby","kong-gateway","kotlin","kubernetes","laravel","libreoffice","lineageos","linux","linuxmint","log4j","logstash","looker","lua","macos","mageia","magento","mariadb","mastodon","matomo","mattermost","maven","mediawiki","meilisearch","memcached","micronaut","microsoft-build-of-openjdk","mongodb","moodle","motorola-mobility","msexchange","mssqlserver","mulesoft-runtime","mxlinux","mysql","neo4j","netbsd","nextcloud","nextjs","nexus","nginx","nix","nixos","nodejs","nokia","nomad","numpy","nutanix-aos","nutanix-files","nutanix-prism","nuxt","nvidia","nvidia-gpu","office","openbsd","openjdk-builds-from-oracle","opensearch","openssl","opensuse","openwrt","openzfs","opnsense","oracle-apex","oracle-database","oracle-jdk","oracle-linux","oracle-solaris","ovirt","pangp","panos","pci-dss","perl","photon","php","phpbb","phpmyadmin","pixel","plesk","pop-os","postfix","postgresql","powershell","prometheus","protractor","proxmox-ve","puppet","python","qt","quarkus-framework","quasar","rabbitmq","rails","rancher","raspberry-pi","react","readynas","red-hat-openshift","redhat-build-of-openjdk","redhat-jboss-eap","redhat-satellite","redis","redmine","rhel","robo","rocket-chat","rocky-linux","ros","ros-2","roundcube","ruby","rust","salt","samsung-mobile","sapmachine","scala","sharepoint","silverstripe","slackware","sles","solr","sonar","splunk","spring-boot","spring-framework","sqlite","squid","steamos","surface","symfony","tails","tarantool","telegraf","terraform","tomcat","traefik","twig","typo3","ubuntu","umbraco","unity","unrealircd","varnish","vcenter","veeam-backup-and-replication","visual-cobol","visual-studio","vmware-cloud-foundation","vmware-harbor-registry","vmware-srm","vue","vuetify","wagtail","watchos","weechat","windows","windows-embedded","windows-server","wordpress","xcp-ng","yarn","yocto","zabbix","zerto","zookeeper"]
    # Check if the software name (without version) is in the EoL list
    return software_name.lower() in (s.lower() for s in EoL_software)


def check_eol_software(software, version):
    # Regular expression to extract software name and version
    
    if is_eol_software(software):
    
        return findSoftwareVersion(software, version)
    else:
        return {"vulnerability": ["None"], "colour": "plain"}
  
    



# Basic CMS Detetction
def get_cms_info(response):

    cms_signatures = {
        'WordPress': 'X-WP',
        'Joomla': 'X-Joomla',
        'Drupal': 'X-Drupal',
        'Magento': 'Magento',
        'Shopify': 'X-Shopify-Stage',
        'PrestaShop': 'PrestaShop',
        'TYPO3': 'TYPO3',
        'Wix': 'X-Wix-Website-Id',
        'Squarespace': 'Squarespace',
        'Blogger': 'blogger',
        'Bitrix': 'Bitrix',
        'Shopware': 'Shopware',
        'WooCommerce': 'woocommerce',
        'BigCommerce': 'BigCommerce',
        'Zen Cart': 'Zen Cart',
        'Umbraco': 'X-Umbraco-Version',
        'SilverStripe': 'SilverStripe',
        'Moodle': 'Moodle',
        'Ghost': 'Ghost',
        'DjangoCMS': 'django',
        'Site Finity' : 'Sitefinity'

        # Additional CMS signatures can be added here
    }

    version_signatures = {
        'generator': [
            'WordPress', 'Joomla', 'Drupal', 'Magento', 'PrestaShop', 'TYPO3', 
            'Shopware', 'WooCommerce', 'BigCommerce', 'Zen Cart', 'Umbraco', 
            'SilverStripe', 'Moodle', 'Ghost', 'DjangoCMS', 'Sitefinity', 'Dynamicweb'
            # Other CMS that include version info in generator meta tag
        ],
        # Other version indicators can be added here
    }

    
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers
        
        # Check headers for CMS
        cms_name, cms_version, vulnerability = None, None, {"vulnerability": ["None"], "colour": "plain"}
        for cms, signature in cms_signatures.items():
            if signature in headers:
                cms_name = cms
                break
        
        # If CMS not detected in headers, check meta tags
        if not cms_name:
            for meta in soup.find_all('meta', attrs={'name': 'generator', 'content': True}):
                content = meta['content']
                for cms in version_signatures['generator']:
                    if cms.lower() in content.lower():
                        cms_name = cms
                        # Attempt to extract version
                        cms_version = content.replace(cms, '').strip()
                        if cms_version:
                            vulnerability = (check_eol_software(cms_name, cms_version))

                        break
                if cms_name:
                    break
        
        return {'CMS':cms_name, 'version':cms_version, 'vulnerability': vulnerability}
    
    except requests.RequestException as e:
        print(f"Error fetching the website: {e}")
        return None



# Redirection Logic
def resolve_to_ip(url_or_domain):
    url_or_domain = re.sub(":\d+$", "", url_or_domain)  # Remove port number if present
    url_or_domain = re.sub(r"https?://([^/]+).*", r"\1", url_or_domain)  # Extract domain
    try:
        return socket.gethostbyname(url_or_domain)
    except socket.gaierror:
        return None


def resolve_ips(url1, url2):
    url1_ip = resolve_to_ip(url1)
    url2_ip = resolve_to_ip(url2)
    return (str(url1_ip).strip()) == (str(url2_ip).strip())
    

def match_urls(url1, url2):
    # Define a regular expression pattern to strip http://, https://, www., and trailing slashes
    pattern = re.compile(r"https?://(www\.)?|:\d+|/$")

    # Remove the protocols, www, and trailing slashes from both URLs
    # Ive added the split code so this may destroy things
    stripped_url1 = (re.sub(pattern, '', url1).strip()).split("/")[0]
    stripped_url2 = (re.sub(pattern, '', url2).strip()).split("/")[0]

    # Compare the processed URLs
    return stripped_url1 == stripped_url2
    
def ip_to_url_condition(url1, url2):
    pattern = re.compile(r"https?://[^\s/]+(\.[^\s/]+)+", re.IGNORECASE)
    if re.match(pattern, url2):
        return (resolve_ips(url1, url2))
    else:
        return (False)

# Redirection Logic Over


def is_direct_ip_accessible(ip, port, scheme):
    url = f"{scheme}://{ip}:{port}"
    try:
        response = requests.get(url, timeout=timeout_value, verify=False)
        if response.status_code == 200:
            return True
    except requests.RequestException:
        pass
    return False


def hashContent(content):
    # Hash the content of the conent for faster comparison
    content = str(content)
    hash_object = hashlib.md5()
    hash_object.update(content.encode())
    md5_hash = hash_object.hexdigest()
    return md5_hash



def check_headers(headers):
    required_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
        ]

    headers_to_remove =[
        "server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Runtime",
        "X-Version",
        "Via",
        "X-Backend-Server",
        "Authorization",
        "Proxy-Authorization",
        "X-Xss-Protection"
    ]

    header_criteria = {
        "X-Frame-Options": lambda value: value in ["SAMEORIGIN", "DENY"],
        "X-Content-Type-Options": lambda value: value == "nosniff",
        "Content-Security-Policy": lambda value: "*" not in value,
        "Strict-Transport-Security": lambda value: all([
            "max-age=31536000" in value,
            "includeSubDomains" in value,
            "preload" in value
        ])
    }




def check_port(IP_addresses):
    global allowRedirects
    entry = IP_addresses[0]
    IP_content = []
    visited_ports = []
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    schemes = ['http', 'https']
    updated_ports_data = []

    required_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
        ]

    headers_to_remove =[
        "server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Runtime",
        "X-Version",
        "Via",
        "X-Backend-Server",
        "Authorization",
        "Proxy-Authorization",
        "X-Xss-Protection"
    ]

    header_criteria = {
        "X-Frame-Options": lambda value: value in ["SAMEORIGIN", "DENY"],
        "X-Content-Type-Options": lambda value: value == "nosniff",
        "Content-Security-Policy": lambda value: "*" not in value,
        "Strict-Transport-Security": lambda value: all([
            "max-age=31536000" in value,
            "includeSubDomains" in value,
            "preload" in value
        ])
    }


    

    def get_color(header, value):
        if value is None or value == "Missing!":
            return "yellow"
        elif header in header_criteria and header_criteria[header](value):
            return "plain"
        else:
            # Misconfigured
            return "green"

    new_hosts = []
    hosts = entry['host']
    ports = entry['ports']
    for hostCount, host in enumerate(hosts):
        extention = host.split("/")
        strippedHost = extention[0]
        if len(extention) > 1:
            extention = extention[1:]
            extention = "/"+str("/".join(extention))
        else:
            extention = ''
        for port in ports:
            redirectedUrl = False
            if port not in visited_ports:
                for scheme in schemes:
                    url = f"{scheme}://{strippedHost}:{port}{extention}"
                    duplicate = False

                    parsed_url = urlparse(url)
                    netloc = f"{parsed_url.hostname}:{port}"
                    url_with_port = urlunparse((scheme, netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))

                    try:
                        response = requests.get(url, timeout=timeout_value, verify=False)


                        # Check if port changes. This is to stop the redirect function thinking every port that redirects to 443 is open!
                        final_url = response.url
                        final_port = urlparse(final_url).port or (80 if final_url.startswith('http://') else 443)
                        print (f"\nInspecting: {url}")
                        print(f"Started at port {port}, ended up at port {final_port} after redirects.")
                        if str(final_port) == str(port):
                            
                            
                            formatCheck = {"Port": port, "Content":hashContent(response.content)}
                            if formatCheck in IP_content:
                                duplicate = True
                            else:
                                if response.status_code != 400:
                                    IP_content.append({"Port": port, "Content":hashContent(response.content)})
                                else:
                                    pass

                            if duplicate == False:
                                time.sleep(1)

                                final_scheme = response.url.split(':')[0]  # Extracts 'http' or 'https' from the final URL
                                if final_scheme != scheme:
                                    print(f"Scheme changed from {scheme} to {final_scheme} for {host}:{port}")
                                    scheme = final_scheme





                                # Dont even ask me whats going on here I hate Redirects!!!!
                                original_url = url
                                final_url = response.url
                                for resp in response.history:
                                    if resp.status_code in (301, 302):
                                        patternUrl = re.compile(r"https?://[^\s/]+(\.[^\s/]+)+", re.IGNORECASE)
                                        # Comparing the original and final URLs
                                        if original_url != final_url:
                                            print(f"\n\nOriginal URL: {original_url}")
                                            print(f"Final URL after redirects: {final_url}")
                                            print("\n\nRedirect chain:")
                                            for redirect_response in response.history:
                                                print(f"Redirected from {redirect_response.url} to {redirect_response.headers['Location']}")
                                            
                                            
                                            if re.match(patternUrl, original_url):
                                                same_url = match_urls(original_url, final_url)
                                                print (f"Same URL: {same_url}")
                                                if same_url:
                                                    # Assuming 'formatCheck' and 'IP_content' logic is defined elsewhere
                                                    print ("Overall - In Scope")
                                                    

                                                    
                                                else:
                                                    print ("Overall - Not in Scope")
                                                    redirectedUrl = True
                                            
                                            # IP address redirect
                                            else:
                                                sameIP = resolve_ips(original_url, final_url)
                                                print (f"Same IP: {sameIP}")
                                                ip_to_url = ip_to_url_condition(original_url, final_url)
                                                print (f"Ip to URL condition: {ip_to_url}")
                                                if sameIP:
                                                    print ("Overall - In Scope")
                                                else:
                                                    print ("Overall - Not in Scope")
                                                    redirectedUrl = True


                                if response.status_code != 400 and redirectedUrl == False:
                                    print (f"Success on Host: {strippedHost} Port: {port} Length: {len(response.content)}")
                                    visited_ports.append({"Host":host, "Port":port})

                                    

                                    IP_address = ip_address = socket.gethostbyname(strippedHost)

                                    port_data = {'port': port, 'service': scheme, 'headers': {}, 'headers_to_remove': {}, "direct_ip_access":"False", "IP_address": IP_address}

                                    if re.match(r"\d+\.\d+\.\d+\.\d+", host):  # Simple regex to check if host is an IP address
                                        if is_direct_ip_accessible(host, port, scheme):
                                            port_data['direct_ip_access'] = "True"

                                    
                                    for header in required_headers:
                                        header_value = response.headers.get(header)
                                        value = header_value if header_value is not None else "Missing!"
                                        color = get_color(header, value)
                                        port_data['headers'][header] = {'value': value, 'color': color}

                                    port_data['headers_to_remove'] = check_vulnerable_headers (response.headers)
                                    

                                    if "Access-Control-Allow-Origin" in response.headers:
                                        wildcardCheck = response.headers.get("Access-Control-Allow-Origin")
                                        if wildcardCheck == "*":
                                            (port_data['headers_to_remove'])["Access-Control-Allow-Origin"] = {'data': '*', 'vulnerability': 'Wild Card in use', 'colour': 'green', 'Current-version': None, 'Latest-version': None}

                                    min_content_length = 200
                                    if len(response.content) < min_content_length:
                                        port_data['content_length'] = 'False'
                                    else:
                                        port_data['content_length'] = 'True'

                                    port_data['status_code'] = response.status_code
                                    port_data['status_message'] = response.reason

                                    cms_data = get_cms_info(response)
                                    if cms_data:
                                        port_data['cms'] = cms_data


                                    if hostCount == 0:
                                        updated_ports_data.append(port_data)
                                    else: 
                                        if strippedHost in new_hosts:
                                            for appendHost in IP_addresses:
                                                if appendHost["host"] == strippedHost:
                                                    for portCount, appendPort in enumerate(appendHost["ports"]):
                                                        if port == appendHost["ports"][portCount]:
                                                            appendHost["ports"][portCount] == port_data
                                        else:
                                            IP_addresses.append({'host': [strippedHost], 'ports': [port_data], 'new_host':'True'})
                                            new_hosts.append(strippedHost)
                                
                                else:
                                    print (f"Scheme Switched, Skipping: {strippedHost}:{port} over {scheme}")

                        else:
                            print ("Port Switched, Skipping:", strippedHost, ":", port)
                    except requests.RequestException as e:
                        pass
        
        
    entry['ports'] = updated_ports_data
  
    return (IP_addresses)



def check_web_services(data, timeout, threads_value):
    updated_data = []
    global timeout_value
    timeout_value = timeout
    
    # Function to wrap check_port call
    def process_entry(entry):
        return check_port([entry])
    
    # Use ThreadPoolExecutor to run check_port in parallel
    with ThreadPoolExecutor(max_workers=threads_value) as executor:
        # Schedule the check_port function for each entry in data
        future_to_entry = {executor.submit(process_entry, entry): entry for entry in data}
        
        for future in concurrent.futures.as_completed(future_to_entry):
            entry = future_to_entry[future]
            try:
                results = future.result()
                for result in results:
                    if result["ports"]:
                        updated_data.append(result)
                    else:
                        print(f"No live ports for {entry['host']}. Removing from list.")
            except Exception as exc:
                print(f'{entry} generated an exception: {exc}')
            
                
    return updated_data
