from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import datetime

timeout_value = 5

def get_ssl_certificate(address):
    """
    Retrieves SSL certificate information for a given hostname and port,
    bypassing SSL certificate verification.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    cert = ''

    target_host = ((address['host'][0]).split("/"))[0]
    for target_port in address['ports']:
        if target_port['service'] == 'https':
            print (f"Checking: {target_host}")
            with socket.create_connection((target_host, int(target_port['port'])), timeout=timeout_value) as sock:
                with context.wrap_socket(sock, server_hostname=target_host) as sslsock:
                    der_cert = sslsock.getpeercert(binary_form=True)
                    try:
                        cert = get_certificate_info((x509.load_der_x509_certificate(der_cert, default_backend())), target_host)
                    except:
                        print ("Cert Error")

    if cert:
        target_port["cert_details"] = cert
    
    return (address)



def get_certificate_info(certificate, target_hostname):
    """
    Prints certificate information, focusing on common names for subject and issuer,
    and includes checks for various vulnerabilities.
    """
    # Basic certificate details
    public_key = certificate.public_key()
    public_key_algo = public_key.__class__.__name__.replace("PublicKey", "")
    key_size = public_key.key_size if hasattr(public_key, "key_size") else "Unknown"
    signature_algo = certificate.signature_hash_algorithm.name

    # Extracting subject and issuer CNs
    subject_cn = next((attr.value for attr in certificate.subject if attr.oid == x509.NameOID.COMMON_NAME), None)
    issuer_cn = next((attr.value for attr in certificate.issuer if attr.oid == x509.NameOID.COMMON_NAME), None)

    # Date and security checks
    validity_start = certificate.not_valid_before_utc
    validity_end = certificate.not_valid_after_utc
    current_date = datetime.datetime.now(datetime.timezone.utc)

    is_self_signed = subject_cn == issuer_cn
    is_expired = current_date > validity_end
    has_started = current_date < validity_start
    is_close_to_expiring = 0 < (validity_end - current_date).days <= 30
    is_too_long = (validity_end - validity_start).days > 825
    uses_weak_hash = signature_algo.lower() in ["md5", "sha1"]
    is_key_too_short = key_size < 2048
    is_wildcard = "*" in subject_cn if subject_cn else False
    hostname_mismatch = target_hostname.lower() != subject_cn.lower() if subject_cn else True

    # Formatting dates for output
    formatted_start = validity_start.strftime("%d-%m-%Y")
    formatted_end = validity_end.strftime("%d-%m-%Y")

    certificate_details = {
        "Subject_CN": subject_cn,
        "Issuer_CN": issuer_cn,
        "Validity_Start": formatted_start,
        "Validity_End": formatted_end,
        "Public_Key_Algorithm": public_key_algo,
        "Key_Size": key_size,
        "Signature_Algorithm": signature_algo,
        "Vulnerabilities": {
            "is_self_signed": {"Value": is_self_signed, "Colour": "Yellow"},
            "is_expired": {"Value": is_expired, "Colour": "Yellow"},
            "has_started": {"Value": has_started, "Colour": "Yellow"},
            "is_close_to_expiring": {"Value": is_close_to_expiring, "Colour": "Blue"},
            "is_too_long": {"Value": is_too_long, "Colour": "Green"},
            "uses_weak_hash": {"Value": uses_weak_hash, "Colour": "Green"},
            "is_key_too_short": {"Value": is_key_too_short, "Colour": "Green"},
            "is_wildcard": {"Value": is_wildcard, "Colour": "Blue"},
            "hostname_mismatch": {"Value": hostname_mismatch, "Colour": "Yellow"}
        }
    }

    return certificate_details



def findSSLCert(IP_addresses, threads_value, timeout):
    global timeout_value
    timeout_value = timeout

    def process_address(address):
        return get_ssl_certificate(address)

    with ThreadPoolExecutor(max_workers=threads_value) as executor:
        results = executor.map(process_address, IP_addresses)
    
    return list(results)


#print (findSSLCert([{'host': ['www.jackmason.com'], 'ports': [{'port': '443', 'service': 'https', 'headers': {'X-Frame-Options': {'value': 'Missing!', 'color': 'yellow'}, 'X-Content-Type-Options': {'value': 'nosniff', 'color': 'plain'}, 'Content-Security-Policy': {'value': '*', 'color': 'green'}, 'Strict-Transport-Security': {'value': 'max-age=31536000; includeSubDomains; preload;', 'color': 'plain'}}, 'headers_to_remove': {'server': {'data': 'Apache', 'vulnerability': 'None', 'colour': 'plain'}, 'X-Xss-Protection': {'data': '1; mode=block', 'vulnerability': 'X-XSS-Protection Deprectaed', 'colour': 'green'}}, 'direct_ip_access': 'False', 'content_length': 'True', 'status_code': 403}]}],1))