#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Floyd Hightower <https://github.com/fhightower>
# June 2016
"""Webpage monitoring script which sends alert if webpage's content changes."""


import argparse
import datetime
import hashlib
import json
import logging
import smtplib
import sys

import requests

CONFIG = {
    # email addresses that will receive an alert if a website changes
    'alert_recipients': [''],
    # path to the json output file with a record of URLs and their hashes
    'json_record_path': "./page_monitor.json",
    # this is the absolute path to the log file
    'log_file_path': "./page_monitor.log",
    'logging_level': logging.WARNING,
    # these are the sites to be monitored
    'sites': {"http://www.quechua.co.uk": ['ski-touring-idfam3660'],
              "http://mirror2.malwaredomains.com/files/domains.txt": []},
    # SMTP server name for the email service you wish to use
    # (for more info, see: http://www.serversmtp.com/en/what-is-my-smtp)
    'smtp_server': "SMTP.GMAIL.COM",
    'user_agent': "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 " +
                  "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
}
CURRENT_DATETIME = str(datetime.datetime.today())


def init_parser():
    """Initialize the argument parser."""
    logging.debug("Initializing the argument parser")

    parser = argparse.ArgumentParser(
        description="Monitor a website and send alerts if it changes.")
    parser.add_argument("email_address", metavar="email_address", type=str,
                        nargs=1, help="an email address from which I can " +
                        "send updates if a webpage changes")
    parser.add_argument("email_account_password", type=str, nargs=1,
                        metavar="email_account_password", help="the " +
                        "password for the email address so that I can " +
                        "send notifications if a webpage changes")

    return parser.parse_args()


def get_previous_hashes():
    """Read the pickle containing the URLs and their hashed content."""
    logging.debug("Retrieving hashes from previous passes")

    try:
        with open(CONFIG['json_record_path'], 'r') as url_hash_json:
            previous_hashes = json.load(url_hash_json)
    except IOError as e:
        logging.error("IOError likely because this is the first pass and " +
                      "the json record file does not yet exist: {}".format(e))
        previous_hashes = {}

    return previous_hashes


def get_website_text(url):
    """Make a request to get the content of the given URL."""
    logging.debug(
        "Making a request to {} in order to get the URL's text".format(url))

    headers = dict()

    if CONFIG['user_agent'] is not None and CONFIG['user_agent'] != "":
        headers['User-Agent'] = CONFIG['user_agent']

    r = requests.get(url, headers=headers)
    return r.text


def get_hash(url, website_text):
    """Get the hash of the website's content."""
    logging.debug("Calculating the hash for {}".format(url))

    website_text_hash = hashlib.md5(website_text.encode("utf-8"))

    return website_text_hash.hexdigest()


def send_alert(changed_url, date_of_last_check):
    """Send an email alert that the content at the given URL has changed."""
    # if there are not alert recipients specified, just add the sender as the
    # recipient
    if not any(CONFIG['alert_recipients']):
        CONFIG['alert_recipients'].append(sys.argv[1])

    logging.debug("Sending an alert from {} to {} email addresses".format(
        sys.argv[1], len(CONFIG['alert_recipients'])))

    # sender config.
    gmail_user = sys.argv[1]
    gmail_pwd = sys.argv[2]
    FROM = gmail_user

    # recipient config.
    TO = ", ".join(CONFIG['alert_recipients'])

    # message config.
    SUBJECT = "Page Monitor Alert: " + changed_url
    TEXT = "The code on the page: " + changed_url + \
        " has changed since it was last checked (" + date_of_last_check + ")."

    # prepare actual message
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, TO, SUBJECT, TEXT)

    # attempt to send the message
    try:
        server = smtplib.SMTP(CONFIG['smtp_server'], 587)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(gmail_user, gmail_pwd)
        server.sendmail(FROM, TO, message)
        server.close()
    except smtplib.SMTPException as e:
        logging.error("Failed to send the alert for {}: ".format(changed_url) +
                      "{}".format(e))


def write_hashes(url_hashes):
    """Write the URL and URL content data to a pickle."""
    logging.debug("Writing URL data to {}.".format(CONFIG['json_record_path']))

    with open(CONFIG['json_record_path'], 'w+') as output_file:
        json.dump(url_hashes, output_file, indent=4, sort_keys=True)
        output_file.close()


def main():
    """Monitor a URL for any changes since the last pass."""
    logging.debug("Starting the main function")

    # parse the command line arguments
    init_parser()

    url_change = False

    # get all of the hashes from the previous pass
    previous_hashes = get_previous_hashes()

    # get a list of all URLs to be examined
    for site in CONFIG['sites']:
        files = CONFIG['sites'][site]

        # if there are no files given, monitor the URL
        if not any(files):
            files.append("")

        for file in files:
            url = site + "/" + file
            # get the content of the URL
            website_text = get_website_text(url)

            # get the hash of each URL
            website_text_hash = get_hash(url, website_text)

            # if we have the hash for this site already...
            if url in previous_hashes:
                # compare this hash to the previous pass and send an alert if
                # there is a difference
                if (previous_hashes[url]['md5'] != website_text_hash):
                    # something is different... sound the alarm!
                    send_alert(url, CURRENT_DATETIME)

                    # redefine the hash value for this website's text to be the
                    # new hash
                    previous_hashes[url]['md5'] = website_text_hash
                    previous_hashes[url]['last_changed'] = CURRENT_DATETIME
                    url_change = True

            # if we do not have the hash for this site already...
            else:
                # record the value of this new URL and the timestamp
                previous_hashes[url] = {
                    'last_changed': CURRENT_DATETIME,
                    'md5': website_text_hash
                }
                url_change = True

    # if URL content has been added or changed, record the new hash for the
    # URL content
    if url_change:
        # write the new value to a pickle
        write_hashes(previous_hashes)


if __name__ == '__main__':
    # setup logging
    log_format = '%(asctime)s %(levelname)s: %(message)s [%(funcName)s :: ' + \
                 '%(lineno)d]'
    logging.basicConfig(filename=CONFIG['log_file_path'], filemode='w',
                        level=CONFIG['logging_level'], format=log_format)

    main()
