
## WordPress Admin Account Creation and Reverse Shell (cve-2024-27956)
 
This Python script automates the process of creating a new administrator account in a WordPress site and executing a reverse shell on the target server. It utilizes the wp-automatic plugin's CSV injection vulnerability to execute SQL queries on the WordPress database and gain administrative access.

 
## update 🦹‍♀️

### add multiple targets support
### add Auto find target by scanners base ip or txt file 

## Prerequisites

- Python 3.x
- `requests` library (install via `pip install requests`)
- Netcat (for setting up a listener to connect to the reverse shell)

## Usage

1. Replace the `domain` variable in the script with the URL of the target WordPress site.
2. Run the Python script.
3. Once the script is executed, it will create a new admin user named `eviladmin`, set the password, and assign administrative privileges.
4. It will then upload and execute a reverse shell payload on the target server.
5. Set up a netcat listener to connect to the reverse shell using the specified port.

**Note:** Ensure that you have proper authorization and permissions before running this script, as it can lead to security vulnerabilities and legal consequences if misused.

## Disclaimer

This script is provided for educational and testing purposes only. The author assumes no liability for any unauthorized or illegal use of this script. Use it at your own risk.
