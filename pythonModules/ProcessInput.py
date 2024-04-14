import re, socket


def resolve_domain(domain_name):
    hasWWW = False
    if domain_name[3:] == 'www':
        hasWWW = True
    
    try:
        try:
            # Resolve the domain to an IP address
            ip_address = socket.gethostbyname(domain_name)
            print (f'{domain_name} successfully resolved to {ip_address}')
            return [ip_address, domain_name]

        except:
            print (f'The domain {domain_name} did not successfully resolve on the first attempt!')
            if hasWWW:
                domain_name = re.sub(r'^www\.', '', domain_name)
            else:
                domain_name = 'www.' + domain_name
            ip_address = socket.gethostbyname(domain_name)
            print (f'{domain_name} successfully resolved to {ip_address}')
            return [ip_address, domain_name]

    except Exception as e:
        print(f"Error in resolving the domain: {domain_name}\n {e}")
        # Catch exceptions related to domain resolution
        return False




def sanitise_url(url):
    """Sanitise the given URL."""
    url = re.sub(r'^https?://', '', url)  # Remove http:// or https://
    #url = re.sub(r'^www\.', '', url)  # Remove www.
    port_input = url.split(":")
    if len(port_input) > 1:
        port_input_combined = ':'
        for character in port_input[1]:
            if (character).isnumeric() == True:
                port_input_combined+=character
            elif character == ',':
                port_input_combined+=character
            else:
                break
        port_input = port_input_combined
        
    else:
        port_input = ""

    url = url.replace(port_input, "")

    extension_parts = url.split("/")
    if len(extension_parts) > 1:
        # Only consider it an extension if there's content after the slash
        extension = "/".join(extension_parts[1:]) if extension_parts[1] else "False"
    else:
        extension = "False"

    url = extension_parts[0] + port_input  # Combine domain with port if any
    url = url.split("#")[0]
    url = url.split("?")[0]

    return [url, extension]



def process_text_input(input_field, IP_addresses):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

    for address in input_field:
        # This may break the code. Was added last minute to remove any spaces around an input
        address = address.strip()

        split_address = sanitise_url(address)
        sanitised_address = split_address[0]
        if split_address[1] != "False":
            extension = "/" + split_address[1]
        else:
            extension = ""

        domain_part = sanitised_address.split(":")[0] if ":" in sanitised_address else sanitised_address
        port_parts = sanitised_address.split(":")[1].split(",") if ":" in sanitised_address else []
        resolved_ip_and_domain = (resolve_domain(domain_part))

        if resolved_ip_and_domain:
            urlIP, resolved_domain = resolved_ip_and_domain
            resolved_domain_with_extension = resolved_domain + extension
            ip_found = False

            for ip in IP_addresses:
                if urlIP in ip["host"] or resolved_domain_with_extension in ip["host"]:
                    # Merge ports if the IP or domain is already present
                    ip["ports"] = list(set(ip["ports"] + port_parts))
                    if resolved_domain_with_extension not in ip["host"]:
                        ip["host"].append(resolved_domain_with_extension)
                    ip_found = True
                    break

            if not ip_found:
                # If there's no matching IP, add a new entry
                new_entry_ports = port_parts if port_parts else ['80', '443', '8080', '8443']
                IP_addresses.append({'host': [resolved_domain_with_extension], 'ports': new_entry_ports})


    return IP_addresses
