#! /usr/bin/env python3

from flask import Flask, render_template, request, jsonify
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from flask import Flask, render_template, request, redirect, url_for
import validators
import requests, re
from multiprocessing import Pool
import signal, threading
import socket
import nmap,re
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import HTTPError, Timeout
import urllib3, datetime
import sqlite3
from sqlite3 import Error
import os, json, traceback
from urllib.parse import urlparse
from flask_socketio import SocketIO, emit
from flask_cors import CORS


import sys
sys.path.insert(0, 'pythonModules/')


from ProcessInput import process_text_input
from ParseNmap import process_nmap_file
from FindSoftware import findSoftware
from FindHeaders import check_web_services
from FindSSLCiphers import findSSLCiphers
from FindCertPassive import findSSLCert
from FindOptions import findOptions
from FindbasicDirectories import findBasicDirectories


# Global Module
ssl_scan_option = True
ssl_cert_option = True
NmapScanOn = False
cookies_options = False
httpMethods_option = False
save_option = False
software_option = False
basic_directories_option = False
brute_force_option = False
screenshots_option = False
threads_value = 2
timeout_value = 5
delay_value = 100


DATABASE = 'databaseFiles/database.db'


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app,resources={r"/*":{"origins":"*"}})
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def insert_web_scanner(conn, web_scanner):
    """
    Insert a new row into the web_scanner table
    :param conn:
    :param web_scanner: (date, name, data)
    :return: web_scanner id
    """
    sql = ''' INSERT INTO web_scanner(date, name, data)
              VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, web_scanner)
    conn.commit()
    return cur.lastrowid


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with app.app_context():
        db = get_db_connection()
        with app.open_resource('databaseFiles/schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        conn = get_db_connection()
        with conn:
            cur = conn.cursor()
            cur.execute('INSERT INTO user (scanType) VALUES (?)', ("{'scanType': 'Passive', 'save': True, 'httpMethods': False, 'cookies': False, 'bruteForce': False, 'software': True, 'basicDirectories': True, 'sslCiphers': False, 'certificate': True, 'screenshots': True, 'threads': 2, 'timeout': 5, 'delay': 100}",))
            conn.commit()


def query_db(query, args=(), one=False):
    cur = get_db_connection().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def delete_all_contents(db_file):
    """
    Delete all contents from the SQLite database.

    :param db_file: Database file path.
    """
    # Establish a connection to the database
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Retrieve a list of all tables in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        # Loop through all tables and delete their contents
        for table in tables:
            print(f"Deleting contents of table: {table[0]}")
            cursor.execute(f"DELETE FROM {table[0]};")
        
        # Commit the changes
        conn.commit()
        print("All contents deleted successfully.")
        
    except Error as e:
        print(f"An error occurred: {e}")
        
    finally:
        if conn:
            # Close the connection to the database
            conn.close()


@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('response', {'data': 'Connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


def perform_scan(request, scanName):
    IP_addresses = []

    print ("\n<------------- START ------------->\n")
    socketio.emit('scan_status', {'message': 'Parsing Input'}, namespace='/')



    # ----- Process nmap file -----
    if 'nmapFile' in request.files:
        file = request.files['nmapFile']
        if file.filename != '':
            parsed_data = process_nmap_file(file)
            for ip in parsed_data:
                IP_addresses.append(ip)


    # ----- Text Field Input -----
    if 'url' in request.form:
        IP_addresses = process_text_input(request.form['url'].splitlines(), IP_addresses)

            
    print ("\n<------------- HEADERS MODULE ------------->\n")
    socketio.emit('scan_status', {'message': 'Finding Web Pages'}, namespace='/')


    IP_addresses = check_web_services(IP_addresses, timeout_value, threads_value)

    try:
        if software_option == True or cookies_options == True or screenshots_option == True:
            print ("\n<------------- SOFTWARE, COOKIES AND SCREENSHOTS MODULE ------------->\n")
            if software_option == True:
                socketio.emit('scan_status', {'message': 'Finding Software'}, namespace='/')

            IP_addresses = findSoftware(IP_addresses, cookies_options, software_option, screenshots_option, timeout_value, threads_value, delay_value)
    except Error as e:
        print ('\nError in the Software Module:\n',e)

    try :
        if httpMethods_option == True:
            print ("\n<------------- HTTP MODULE ------------->\n")
            socketio.emit('scan_status', {'message': 'Finding HTTP Methods'}, namespace='/')
            IP_addresses = findOptions(IP_addresses, timeout_value, threads_value)
    
    except Error as e:
        print ('\nError in the HTTP Module:\n',e)

    try:
        if basic_directories_option == True:
            if brute_force_option == False:
                print ("\n<------------- DIRECTORIES MODULE ------------->\n")
                socketio.emit('scan_status', {'message': 'Finding Directories'}, namespace='/')
                IP_addresses = findBasicDirectories(IP_addresses, "basic", timeout_value, threads_value, delay_value)
    
    except Error as e:
        print ('\nError in the DIRECTORIES Module:\n',e)

    try:
        if brute_force_option == True:
            print ("\n<------------- FUZZING MODULE ------------->\n")
            socketio.emit('scan_status', {'message': 'Fuzzing Directories'}, namespace='/')
            IP_addresses = findBasicDirectories(IP_addresses, "brute", timeout_value, threads_value, delay_value)
    
    except Error as e:
        print ('\nError in the FUZZING Module:\n',e)

    try:
        if ssl_scan_option == True:
            print ("\n<------------- CIPHERS MODULE ------------->\n")
            socketio.emit('scan_status', {'message': 'Finding SSL Ciphers'}, namespace='/')
            IP_addresses = findSSLCiphers(IP_addresses, threads_value)
    
    except Error as e:
        print ('\nError in the CIPHERS Module:\n',e)

    try:
        if ssl_cert_option == True:
            print ("\n<------------- CERTIFICATE MODULE ------------->\n")
            socketio.emit('scan_status', {'message': 'Finding SSL Certificate'}, namespace='/')
            IP_addresses = findSSLCert(IP_addresses, threads_value, timeout_value)
    
    except Error as e:
        print ('\nError in the CERTIFICATE Module:\n',e)


    print ("\n<------------- COMPLETED ------------->\n")
    socketio.emit('scan_status', {'message': 'Scan Completed'}, namespace='/')


    # Botch fix to IP address problem (Bulk assign on new host)
    for address in IP_addresses:
        try:
            if address['new_host']:
                address['host'].insert(0, socket.gethostbyname(address['host'][0]))
        except:
            print ("")

    if save_option == True:
        try:
            if IP_addresses != []:
                conn = get_db_connection()
                with conn:
                    cur = conn.cursor()
                    date_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    data_string = json.dumps(IP_addresses)
                    if scanName == "":
                        scanName = str(date_now)
                    cur.execute('INSERT INTO history (name, date, settings, data) VALUES (?, ?, ?, ?)',
                                (scanName, date_now, "", data_string))
                    conn.commit()
        
        except Error as e:
            print ("\nError In saving - ", e, "\n")

    return IP_addresses


@app.route('/save-settings', methods=['POST'])
def save_settings():
    data = request.json
    scan_type = data['scanType']

    data = str(data)    

    if scan_type:
        conn = get_db_connection()
        with conn:
            cur = conn.cursor()
            cur.execute('UPDATE user SET scanType = ?', (data,))
            conn.commit()

        print("Settings Updated: ", data)
        return jsonify({"status": "success", "message": "Settings saved successfully"})
    else:
        return jsonify({"status": "error", "message": "No scan type selected"})



@app.route("/search/<int:search_id>")
def search(search_id):
    previous_searches = query_db('SELECT * FROM history ORDER BY date DESC')
    previous_searches = [dict(row) for row in previous_searches]
    for search in previous_searches:
        
        search['data'] = json.loads(search['data'])

    conn = get_db_connection()
    search_data = conn.execute('SELECT * FROM history WHERE id = ?', (search_id,)).fetchone()
    if search_data is None:
        abort(404)

    ScanName = search_data['name']
    search_data = dict(search_data)['data']
    search_data = json.loads(search_data)
    
    return render_template('search.html', results=search_data, previous_searches=previous_searches, ScanName = ScanName, current_page=search_id)




@app.route("/", methods=['GET', 'POST'])
def index():
    global ssl_scan_option, ssl_cert_option, cookies_options, httpMethods_option, save_option, software_option, basic_directories_option, ssl_scan_option, ssl_cert_option, brute_force_option, screenshots_option, threads_value, timeout_value, delay_value

    try:

        # ----- Get the previous searches -----
        previous_searches = query_db('SELECT * FROM history ORDER BY date DESC')
        previous_searches = [dict(row) for row in previous_searches]

        for search in previous_searches:
            search['data'] = json.loads(search['data'])

        settings = query_db('SELECT scanType FROM user')
        data = (eval(settings[0]['scanType']))
        
        cookies_options = data['cookies']
        httpMethods_option = data['httpMethods']
        save_option = data['save']

        software_option = data['software']
        basic_directories_option = data['basicDirectories']
        ssl_scan_option = data['sslCiphers']
        ssl_cert_option = data['certificate']
        brute_force_option = data['bruteForce']
        screenshots_option = data['screenshots']
        threads_value = data['threads']
        timeout_value = data['timeout']
        delay_value = data['delay']

   
        try:
            scanType = data['scanType']

        except:
            scanType = 'passive'
            
        # ----- Recieve the form submission ----

        if request.method == 'POST':

            scanName = request.form.get('scanName')

            # Split into a function

            scan_output = perform_scan(request, scanName)


            return render_template('search.html', results=scan_output, previous_searches=previous_searches, ScanName = scanName)
        
    except Error as e:
        print ("\nFatal Error Restarting\n", e, "\n")

    return render_template('home.html', data=None, previous_searches=previous_searches, settings=data)


#delete_all_contents('databaseFiles/database.db')


banner = '''


        _   __     __  _____                     _____  ___
       / | / /__  / /_/ ___/_________ _____     / ___/ <  /
      /  |/ / _ \/ __/\__ \/ ___/ __ `/ __ \   / __ \  / / 
     / /|  /  __/ /_ ___/ / /__/ /_/ / / / /  / /_/ / / /  
    /_/ |_/\___/\__//____/\___/\__,_/_/ /_/   \____(_)_/   
                                                       
- by Jack Mason

'''

if __name__ == "__main__":
    print (banner)
    if not os.path.exists(DATABASE):
        init_db()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, port=25250)