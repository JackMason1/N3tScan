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
import os, json, traceback
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time

session = requests.Session()

cookies_option = True
software_options = False
screenshots_options = False
delay_value = 100


def get_latest_version(package_name):
    """
    Get the latest version of a given npm package using a persistent session.
    """
    npm_registry_url = f'https://registry.npmjs.org/{package_name}'
    
    try:
        response = session.get(npm_registry_url, timeout=(5, 14))
        response.raise_for_status()  # This will raise an exception for HTTP errors
        data = response.json()
        return data['dist-tags']['latest']
    except (HTTPError, Timeout) as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")
    return None


def findCVE(package_name, package_version, num_cves=2):  # Added 'num_cves' parameter with a default value
    snyk_url = f'https://security.snyk.io/package/npm/{package_name}/{package_version}'
    base_url = "https://security.snyk.io"

    cve_list = []

    try:
        response = requests.get(snyk_url, timeout=(5, 14))
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        a_elements = soup.find_all('a', attrs={"data-snyk-test": "vuln table title", "class": "vue--anchor"})

        for a_element in a_elements[:num_cves]:  # Process only the first 'num_cves' links
            href = a_element.get('href')
            if href:
                vuln_url = urljoin(base_url, href)
                vuln_response = requests.get(vuln_url, timeout=(5, 14))
                vuln_response.raise_for_status()

                vuln_soup = BeautifulSoup(vuln_response.text, 'html.parser')

                # Extract severity score
                severity_score = vuln_soup.find('div', attrs={"data-snyk-test": "severity widget score"})
                score = severity_score['data-snyk-test-score'] if severity_score and 'data-snyk-test-score' in severity_score.attrs else "Not found"


                # Extract CVE number from the title
                title_tag = vuln_soup.find('title')
                if title_tag:
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', title_tag.get_text())
                    cve = cve_match.group() if cve_match else "Not found"
                else:
                    cve = "Not found"


                # Extract severity level
                severity_level = vuln_soup.find('span', class_="vue--badge__text")
                severity = severity_level.get_text(strip=True) if severity_level else "Not found"

                print(f"CVE: {cve}, Severity Score: {score}, Severity Level: {severity}")
                cve_list.append({"cve":cve, "score":score, "level":severity})

        return cve_list

    except requests.exceptions.RequestException as req_err:
        print(f"HTTP error occurred: {req_err}")
    except Exception as err:
        print(f"An error occurred: {err}")


def is_valid_version(version_str):
    # This function checks if a string contains only numbers and dots
    return re.match(r'^\d+(\.\d+)*$', version_str) is not None


def get_software(address, file):
    for target_host in address['host']:
        for target_port in address['ports']:
            found_software = []
            try:
                results = []

                # This was a quick fix if something breaks its probably this
                extension_parts = target_host.split('/') 
                extension = ''
                if len(extension_parts) > 1:
                    extension = "/"+"/".join(extension_parts[1:])
                    
                strippedHost = extension_parts[0]
                url = f"{target_port['service']}://{strippedHost}:{target_port['port']}{extension}"
                
                options = Options()
                options.set_preference("devtools.toolbox.selectedTool", "console")
                options.set_preference("devtools.toolbox.footer.height", 300)
                #options.set_preference('permissions.default.image', 2)  # Disable images
                options.set_preference('dom.ipc.plugins.enabled.libflashplayer.so', 'false')
                options.set_preference('dom.webnotifications.enabled', False)
                options.set_preference('media.volume_scale', '0.0')  # Disable sounds
                options.set_preference('plugin.scan.plid.all', False)
                options.set_preference('browser.cache.disk.enable', True)
                options.set_preference('browser.cache.memory.enable', True)
                options.set_preference('permissions.default.stylesheet', 2)
                options.add_argument("-headless")

                options.add_argument("--window-size=1920x500")
                
                driver = webdriver.Firefox(options=options)
                #driver.set_page_load_timeout(20)
                driver.implicitly_wait(1)
                driver.set_page_load_timeout(timeout_value+2)
                
                driver.get(url)
                
                if screenshots_option == True:
                    print (f'Taking Screenshot for {url}')
                    saveURL = url.split("#")[0]
                    saveURL = saveURL.split("?")[0]
                    saveURL = saveURL.replace("/", "-")

                    file_name = ".".join(saveURL.split('.')[1:]) +  ".png"  # Simplified file name from URL
                    file_path = os.path.join("static/screenshots", file_name)

                    # Take a screenshot and save it to the specified file path
                    driver.save_screenshot(file_path)

                    target_port["screenshot"] = file_path

                if cookies_option == True:
                    print (f'Getting Cookies for {url}')
                    cookies = driver.get_cookies()

                if software_option == True:

                    for item in file:
                        temp = item.split(":")
                        Library = temp[0]
                        Discover = (str(temp[1]).split('/'))
                        for discover in Discover:
                            if Library not in found_software:
                                time.sleep(delay_value/1000)
                                try:
                                    version = driver.execute_script("return {}".format(str(discover.strip())))
                                    if version:
                                        versionNew = get_latest_version(temp[2].strip())

                                        officialName = (temp[2].strip())

                                        # Check if both versions are valid and compare them
                                        if is_valid_version(version) and is_valid_version(versionNew):
                                            outdated = version != versionNew
                                        else:
                                            outdated = None

                                        cve = findCVE(officialName, version)

                                        found_software.append(Library)

                                        results.append({
                                            "library": Library,
                                            "version": version,
                                            "latest_version": versionNew,
                                            "discover": discover.strip(),
                                            "outdated": outdated,
                                            "officialName": officialName,
                                            "cve": cve
                                            
                                        })
                                except Exception as e:
                                    pass
                            

            

                if cookies_option == True:
                    cookies = driver.get_cookies()
                    if cookies:
                        target_port["cookies"] = cookies
                
                driver.close()

                driver.quit()
                if results:
                    target_port["software"] = results

                


            except Exception as e:
                print (e)
                try:
                    driver.quit()
                except:
                    print ("Driver Error")
                # You may want to log the error or take some action here
                print(f"Error processing port {target_port['port']} for host {target_host}: {e}")
                traceback.print_exc()  # This will print the stack trace

                if screenshots_option == True:
                    target_port["screenshot"] = "static/screenshots/selenium-error-page.png"

        return (address)
                




def findSoftware(IP_addresses, cookies_options, software_options, screenshots_options, timeout, threads_value, delay):
    global cookies_option, software_option, screenshots_option, timeout_value, delay_value
    cookies_option = cookies_options
    software_option = software_options
    screenshots_option = screenshots_options
    timeout_value = timeout
    delay_value = delay

    file = open("javascriptLibaries.txt", "r").read().split("\n")

    def process_address(address):
        return get_software(address, file)

    with ThreadPoolExecutor(max_workers=threads_value) as executor:
        results = executor.map(process_address, IP_addresses)
    
    return list(results)