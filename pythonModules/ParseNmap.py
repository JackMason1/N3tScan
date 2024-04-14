import re



def process_nmap_file(file):
    try:
        file_content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        try:
            file_content = file.read().decode('latin-1')  # Trying a different encoding
        except Exception as e:
            return f"Error decoding file: {e}"

    try:
        return parse_nmap_txt(file_content)
    except Exception as e:
        return f"Error parsing file: {e}"

        

def normalise_newlines(text):
    return text.replace('\r\n', '\n').replace('\r', '\n')


def parse_nmap_txt(file_content):

    print (file_content)
    file_content = normalise_newlines(file_content)

    # Improved regular expressions to match IP addresses and ports
    ip_pattern = r'Nmap scan report for (?:[^\s]+ )?\(?(\d{1,3}(?:\.\d{1,3}){3})\)?'
    port_pattern = r'(\d+)/tcp\s+open'

    ip_matches = re.finditer(ip_pattern, file_content)
    sections = [(match.start(), match.group(1)) for match in ip_matches]

    results = []

    for i in range(len(sections)):
        start = sections[i][0]
        end = sections[i+1][0] if i < len(sections) - 1 else len(file_content)
        section_content = file_content[start:end]
        ip = (sections[i][1]).strip('()')
        raw_ports = re.findall(port_pattern, section_content) 

        if raw_ports:  # Check if the list of ports is not empty
            results.append({
                "host": [ip],
                "ports": raw_ports
            })

    return results



