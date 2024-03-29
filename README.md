# Page Monitor

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/f5d5d8332a48465b8009bbe8ad6fcc01)](https://www.codacy.com/app/fhightower/page-monitor?utm_source=github.com&utm_medium=referral&utm_content=fhightower/page-monitor&utm_campaign=badger)

*What we see depends mainly on what we look for.*
*- John Lubbock*

## Explanation

The first time `page_monitor.py` is run, it will calculate and record the hash value of the content on each of the given websites.  On subsequent runs, it will again calculate the hash of the content on the site and compare this new value with the previous value.  If the new value is different, an alert will be sent from the email address given as a command-line parameter to all of the email addresses listed in the config. at the top of `page_monitor.py`.

This program is designed to be a simple solution for monitoring a website for changes.  It can be easily run as a cronjob.

If you use [ThreatConnect](https://threatconnect.com/), there is a playbook to monitor a webpage [here](https://github.com/fhightower/page-monitor-playbook).

There are more complete services like [Visual Ping](https://visualping.io/) that do the same thing (and more) as this script. I cannot vouch for any of these services as I haven't used them, but you may want to look into them.

## Usage
**usage:** page_monitor.py [-h] email_address email_account_password

Monitor a webpage for changes to its content and send alerts if there are any
changes.

**positional arguments:**

  - **email_address**  an email address from which I can send updates if a
                        webpage changes

  - **email_account_password**  the password for the email address so that I can send notifications if a webpage changes

**optional arguments:**
  
  - **-h, --help**  show this help message and exit
