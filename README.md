# Page Monitor

*What we see depends mainly on what we look for.*
*- John Lubbock*

## Explaination

The first time `page_monitor.py` is run, it will calculate and record the hash value of the content on each of the given websites.  On subsequent runs, it will again calculate the hash of the content on the site and compare this new value with the previous value.  If the new value is different, an alert will be sent from the email address given as a command-line parameter to all of the email addresses listed in the config. at the top of `page_monitor.py`.

This program is designed to be a simple solution for monitoring a website for changes.  It can be easily run as a cronjob.


## Usage
usage: page_monitor.py [-h] email_address email_account_password

Monitor a webpage for changes to its content and send alerts if there are any
changes.

positional arguments:
  email_address         an email address from which I can send updates if a
                        webpage changes
  email_account_password
                        the password for the email address so that I can send
                        notifications if a webpage changes

optional arguments:
  -h, --help            show this help message and exit
