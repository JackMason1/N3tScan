from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import warnings, time
from bs4 import BeautifulSoup
import re, requests, json
from datetime import datetime


# Suppress only the single InsecureRequestWarning from urllib3 needed for `verify=False`
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)


session = requests.Session()
directories = []
timeout_value = 5
delay_value = 100

def hashContent(content, visited_pages):
    # Hash the content for faster comparison
    content = str(content)
    hash_object = hashlib.md5(content.encode())
    md5_hash = hash_object.hexdigest()
    if md5_hash in visited_pages:
        return visited_pages
    else:
        visited_pages.add(md5_hash)  # Corrected to add md5_hash to the set
        return visited_pages



def check_security_headers(headers):
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

    required_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
    ]

    header_list = {}
    for header in required_headers:
        header_value = headers.get(header, "Missing!")  # Default to "Missing!" if header is not found
        # Determine the color based on the header criteria
        if header_value == "Missing!" or header_value is None:
            color = "yellow"
        elif header in header_criteria and header_criteria[header](header_value):
            color = "plain"
        else:
            color = "green"
        header_list[header] = {'value': header_value, 'color': color}

    return header_list




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
            return ({"vulnerability":["HTTP Header Version Disclosure", "End-of-Life-Software"], "colour": "red", "Current-version":version, "Latest-version": latest_version})
           
        elif version < correctCycle["latest"]:  
            print (f"\nOutdated {software}")
            latest_version = result[0]["latest"]  # Store the latest version in a variable
            print(f"Latest version = {latest_version} Current version = {version}")   
            return ({"vulnerability":["HTTP Header Version Disclosure", "Outdated-Software"], "colour": "yellow", "Current-version":version, "Latest-version": latest_version})

        else:
            print (f"\n{software} Up to date!\n")
            latest_version = result[0]["latest"]
            return {"vulnerability": ["HTTP Header Version Disclosure"], "colour": "blue"}
    except:
        print (f"\nError with library {software}\n")
        return {"vulnerability": ["HTTP Header Version Disclosure"], "colour": "yellow"}



def is_eol_software(software_name):
    # Define the EoL software list
    EoL_software = ["akeneo-pim","alibaba-dragonwell","almalinux","alpine","amazon-cdk","amazon-corretto","amazon-eks","amazon-glue","amazon-linux","amazon-neptune","amazon-rds-mysql","amazon-rds-postgresql","android","angular","angularjs","ansible","ansible-core","antix","apache","apache-activemq","apache-airflow","apache-camel","apache-cassandra","apache-groovy","apache-hadoop","apache-hop","apache-kafka","apache-spark","apache-struts","api-platform","apple-watch","arangodb","argo-cd","artifactory","aws-lambda","azul-zulu","azure-devops-server","azure-kubernetes-service","bazel","beats","bellsoft-liberica","blender","bootstrap","bun","cakephp","centos","centos-stream","centreon","cert-manager","cfengine","chef-infra-server","citrix-vad","ckeditor","clamav","cockroachdb","coldfusion","composer","confluence","consul","containerd","contao","cortex-xdr","cos","couchbase-server","craft-cms","dbt-core","debian","dependency-track","devuan","django","docker-engine","dotnet","dotnetfx","drupal","drush","eclipse-jetty","eclipse-temurin","elasticsearch","electron","elixir","emberjs","envoy","erlang","esxi","etcd","eurolinux","exim","fairphone","fedora","ffmpeg","filemaker","firefox","flux","fortios","freebsd","gerrit","gitlab","go","goaccess","godot","google-kubernetes-engine","google-nexus","gorilla","graalvm","gradle","grafana","grails","graylog","gstreamer","haproxy","hashicorp-vault","hbase","horizon","ibm-aix","ibm-i","ibm-semeru-runtime","icinga-web","intel-processors","internet-explorer","ionic","ios","ipad","ipados","iphone","isc-dhcp","istio","jekyll","jenkins","jhipster","jira-software","joomla","jquery","jreleaser","kde-plasma","keda","keycloak","kibana","kindle","kirby","kong-gateway","kotlin","kubernetes","laravel","libreoffice","lineageos","linux","linuxmint","log4j","logstash","looker","lua","macos","mageia","magento","mariadb","mastodon","matomo","mattermost","maven","mediawiki","meilisearch","memcached","micronaut","microsoft-build-of-openjdk","mongodb","moodle","motorola-mobility","msexchange","mssqlserver","mulesoft-runtime","mxlinux","mysql","neo4j","netbsd","nextcloud","nextjs","nexus","nginx","nix","nixos","nodejs","nokia","nomad","numpy","nutanix-aos","nutanix-files","nutanix-prism","nuxt","nvidia","nvidia-gpu","office","openbsd","openjdk-builds-from-oracle","opensearch","openssl","opensuse","openwrt","openzfs","opnsense","oracle-apex","oracle-database","oracle-jdk","oracle-linux","oracle-solaris","ovirt","pangp","panos","pci-dss","perl","photon","php","phpbb","phpmyadmin","pixel","plesk","pop-os","postfix","postgresql","powershell","prometheus","protractor","proxmox-ve","puppet","python","qt","quarkus-framework","quasar","rabbitmq","rails","rancher","raspberry-pi","react","readynas","red-hat-openshift","redhat-build-of-openjdk","redhat-jboss-eap","redhat-satellite","redis","redmine","rhel","robo","rocket-chat","rocky-linux","ros","ros-2","roundcube","ruby","rust","salt","samsung-mobile","sapmachine","scala","sharepoint","silverstripe","slackware","sles","solr","sonar","splunk","spring-boot","spring-framework","sqlite","squid","steamos","surface","symfony","tails","tarantool","telegraf","terraform","tomcat","traefik","twig","typo3","ubuntu","umbraco","unity","unrealircd","varnish","vcenter","veeam-backup-and-replication","visual-cobol","visual-studio","vmware-cloud-foundation","vmware-harbor-registry","vmware-srm","vue","vuetify","wagtail","watchos","weechat","windows","windows-embedded","windows-server","wordpress","xcp-ng","yarn","yocto","zabbix","zerto","zookeeper"]
    # Check if the software name (without version) is in the EoL list
    return software_name.lower() in (s.lower() for s in EoL_software)


def check_version_disclosure(header, value):
    # Regular expression to extract software name and version
    match = re.search(r'(\w+)/?(\d+\.\d+(\.\d+)?)?', value, re.IGNORECASE)
    if match:
        software_name = match.group(1)  # Extract software name
        # Strip version from the software name if present
        softwareSplit = value.split("/")
        if len (softwareSplit) > 1:
            if is_eol_software(software_name):
            
                return findSoftwareVersion(softwareSplit[0], (softwareSplit[1].split("("))[0])
            else:
                return {"vulnerability": ["HTTP Header Version Disclosure"], "colour": "yellow"}
        else:
            return {"vulnerability": ["None"], "colour": "plain"}
    return {"vulnerability": ["None"], "colour": "plain"}




def check_vulnerable_headers(headers):
    vulnerabilities = {
        "server": lambda v: check_version_disclosure("server", v),
        "X-Powered-By": lambda v: check_version_disclosure("X-Powered-By", v),
        "X-Xss-Protection": lambda v: {"vulnerability": "X-XSS-Protection Deprecated", "colour": "green"} if v in ["1; mode=block", "1"] else {"vulnerability": ["None"], "colour": "plain"},
        "X-AspNet-Version": lambda v: {"vulnerability": ["HTTP Header Version Disclosure"], "colour": "yellow"} if re.search(r'\d+\.\d+', v) is not None else {"vulnerability": ["None"], "colour": "plain"},
        "X-AspNetMvc-Version": lambda v: {"vulnerability": ["HTTP Header Version Disclosure"], "colour": "yellow"} if re.search(r'\d+\.\d+', v) is not None else {"vulnerability": ["None"], "colour": "plain"},
        "X-owa-Version": lambda v: {"vulnerability": ["HTTP Header Version Disclosure"], "colour": "yellow"} if re.search(r'\d+\.\d+', v) is not None else {"vulnerability": ["None"], "colour": "plain"},
    }



    headers_to_remove = [
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

    vulnerable_header_list = {}

    for bad_header in headers_to_remove:
        header_value = headers.get(bad_header)
        if header_value:
            vulnerability_info = vulnerabilities.get(bad_header, lambda x: {"vulnerability": ["Unknown Vulnerability"], "colour": "plain"})(header_value)
            vulnerable_header_list[bad_header] = {
                "data": header_value,
                "vulnerability": (vulnerability_info['vulnerability']),
                "colour": vulnerability_info['colour'],
                "Current-version": vulnerability_info.get("Current-version", None),  # Default to None if not present
                "Latest-version": vulnerability_info.get("Latest-version", None)  # Default to None if not present
            }
        

    return vulnerable_header_list



def check_headers(headers_found, code, security_headers, headers_to_remove, page_content):
    
    color_priority = {"yellow": 1, "green": 2, "plain": 3}

    new_security_headers = (check_security_headers(headers_found))
    new_headers_to_remove = (check_vulnerable_headers(headers_found))
    
    if page_content == True:
        for key, value in security_headers.items():
            if key in new_security_headers and color_priority[new_security_headers[key]['color']] < color_priority[value['color']]:
                security_headers[key] = new_security_headers[key]

    for key, value in new_headers_to_remove.items():
        if key not in headers_to_remove:
            headers_to_remove[key] = value

    return ({'headers_to_remove': headers_to_remove, 'security_headers': security_headers})


def check_page(url, directory, visited_pages):
    Directory = ""
    Colour = ""

    time.sleep(delay_value/1000)
    strippedUrl = url.split("/")
    strippedUrl = strippedUrl[0]+"//"+strippedUrl[2]
    search_url = f"{strippedUrl}/{directory}"
    try:
        # Bypass SSL certificate verification
        response = session.get(search_url, timeout=timeout_value, verify=False)

        print ("Checking - ", search_url, response.status_code)

        #time.sleep(0.5)
        
        soup = BeautifulSoup(response.content, 'html.parser')

        # Look for input, textarea, and select tags
        input_tags = soup.find_all('input')
        textarea_tags = soup.find_all('textarea')
        select_tags = soup.find_all('select')

        total_fields = len(input_tags) + len(textarea_tags) + len(select_tags)

        if total_fields > 0:
            input_field = True
        else:
            input_field = False

        currentLength = len(visited_pages)

        visited_pages = hashContent(response.content, visited_pages)

        if currentLength != len(visited_pages) :
            Directory = f"{strippedUrl}/{directory}"
            if response.status_code >= 200 and response.status_code < 300:
                Colour = "green"  # Success responses
            elif response.status_code >= 300 and response.status_code < 400:
                Colour = "blue"  # Redirection messages
            elif response.status_code >= 400 and response.status_code < 500:
                if (len(response.content)) > 400:
                    print ("Length was to long - assuming its not a real error page")
                    return None

                Colour = "red"  # Client error responses
            elif response.status_code >= 500:
                Colour = "orange"
            else:
                Colour = "gray"
        else:
            return None

    except Exception as e:
        print (e)

    if Directory:
        return {"Directory":Directory, "Colour": Colour, "Link": directory, "Code": response.status_code, "Headers": response.headers, "Input": input_field, "Length": len(response.content)}


def check_vulnerability(address):
    global directories
    
    target_host = address['host'][0]
    for target_port in address['ports']:
        interesting_links = []
        visited_pages = set()
        port = target_port["port"]
        security_headers = target_port['headers']
        headers_to_remove = target_port['headers_to_remove']
        url = f"{target_port['service']}://{target_host}:{target_port['port']}"

        for count, directory in enumerate(directories):
            result = check_page(url, directory, visited_pages)  # Pass visited_pages

            

            if result:                
                if count != 0:
                    newHeaders = check_headers(result['Headers'], result['Code'], security_headers, headers_to_remove, result["Input"])
                    security_headers = newHeaders['security_headers']
                    headers_to_remove = newHeaders['headers_to_remove']
                    interesting_links.append({"URL":result['Directory'], "Colour":result['Colour'], "Directory":result['Link'], "Code":result['Code'], "Length":result["Length"]})
                
                elif count == 0 and result['Code'] != 200:
                    newHeaders = check_headers(result['Headers'], result['Code'], security_headers, headers_to_remove, result["Input"])
                    security_headers = newHeaders['security_headers']
                    headers_to_remove = newHeaders['headers_to_remove']
                    interesting_links.append({"URL":result['Directory'], "Colour":result['Colour'], "Directory":result['Link'], "Code":result['Code']})

        if interesting_links:
            target_port["interesting_links"] = interesting_links
                            

    return (address)



def findBasicDirectories(IP_addresses, option, timeout, threads_value, delay):
    global directories, timeout_value, delay_value

    timeout_value = timeout
    delay_value = delay

    if option == 'brute':
        directories = (open("directories_file.txt", "r").read()).split("\n")
    else:
        directories = ['test_break_page', 'admin', 'sitemap.xml', 'robots.txt']
        
    def process_address(address):
        return check_vulnerability(address)

    with ThreadPoolExecutor(max_workers=threads_value) as executor:
        results = executor.map(process_address, IP_addresses)
    
    return list(results)


#print(findBasicDirectories([{'host': ['www.masontech.com'], 'ports': [{'port': '80', 'service': 'http', 'headers': {'X-Frame-Options': {'value': 'Missing!', 'color': 'yellow'}, 'X-Content-Type-Options': {'value': 'Missing!', 'color': 'yellow'}, 'Content-Security-Policy': {'value': 'Missing!', 'color': 'yellow'}, 'Strict-Transport-Security': {'value': 'Missing!', 'color': 'yellow'}}, 'headers_to_remove': {'server': {'data': 'Apache/2.4.18 (Ubuntu)', 'vulnerability': 'HTTP Header Version Disclosure', 'colour': 'yellow'}}, 'direct_ip_access': 'False', 'content_length': 'True'}, {'port': '443', 'service': 'https', 'headers': {'X-Frame-Options': {'value': 'Missing!', 'color': 'yellow'}, 'X-Content-Type-Options': {'value': 'Missing!', 'color': 'yellow'}, 'Content-Security-Policy': {'value': 'Missing!', 'color': 'yellow'}, 'Strict-Transport-Security': {'value': 'Missing!', 'color': 'yellow'}}, 'headers_to_remove': {'server': {'data': 'Apache/2.4.18 (Ubuntu)', 'vulnerability': 'HTTP Header Version Disclosure', 'colour': 'yellow'}}, 'direct_ip_access': 'False', 'content_length': 'True'}]}], 'basic'))