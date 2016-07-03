#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Floyd Hightower <https://github.com/fhightower>
# June 2016
"""A webpage monitoring script designed to be periodically run using a cronjob or similar, task scheduling application."""


import argparse
from datetime import datetime
import hashlib
import logging
import requests
import smtplib
import sys

import pickle


config = {
    # these are email addresses that will recieve an update when there is a change
    'alert_recipients': [''],
    # this is the absolute path to the log file
    'log_file_path': "./page_monitor.log",
    'logging_level': logging.WARNING,
    # these are the sites to be monitored
    'sites': {"http://www.quechua.co.uk": ['ski-touring-idfam3660'], "http://mirror2.malwaredomains.com/files/domains.txt": []},
    # this is the SMTP server name for the service you are using to send an alert email when the content of a URL changes (for a list of smtp servers, see: http://www.serversmtp.com/en/what-is-my-smtp)
    'smtp_server': "SMTP.GMAIL.COM",
    # this is the absolute path to the file containing a pickle of the dictionary with the hashes for each URL
    'url_hash_record_path': "./url_hashes.pickle"
}


def init_parser():
    """Initialize the argument parser."""
    logging.debug("initializing the argument parser")

    parser = argparse.ArgumentParser(description='Monitor a webpage and send alerts if there are any changes.')
    parser.add_argument('email_address', metavar="email_address", type=str, nargs=1, help='an email address from which I can send updates if a webpage changes')
    parser.add_argument('email_account_password', metavar="email_account_password", type=str, nargs=1, help='the password for the email address so that I can send notifications if a webpage changes')

    return parser.parse_args()


def get_previous_hashes():
    """Read the pickle containing the dictionary of the hashes URLs and the hashes of their contents."""
    logging.debug("reading the pickle containing hashes from previous passes")

    try:
        with open(config['url_hash_record_path'], 'rb') as url_hash_dict:
            previous_hashes = pickle.load(url_hash_dict)
    except IOError:
        previous_hashes = {}

    return previous_hashes


def get_website_text(url):
    """Make a request to get the content of the given URL."""
    logging.debug("making a request to {} in order to get the URL's text".format(url))

    r = requests.get(url)
    return r.text


def get_hash(url, website_text):
    """Get the hash of the URL itself and its content."""
    logging.debug("calculating the hash for {}".format(url))

    url_hash = hashlib.md5(url.encode("utf-8"))
    website_text_hash = hashlib.md5(website_text.encode("utf-8"))

    return url_hash.hexdigest(), website_text_hash.hexdigest()


def send_alert(changed_url, date_of_last_check):
    """Send an alert that the content of a URL has changed to the recipients specified in the config. from the email address given as a command-line argument."""
    logging.debug("sending an alert from {} to {} email addresses".format(sys.argv[1], len(config['alert_recipients'])))

    # sender config.
    gmail_user = sys.argv[1]
    gmail_pwd = sys.argv[2]
    FROM = gmail_user

    # recipient config
    TO = ", ".join(config['alert_recipients'])

    # message config.
    SUBJECT = "Page Monitor Alert: " + changed_url
    TEXT = "The code on the page: " + changed_url + " has changed since it was last checked (" + date_of_last_check + ")."

    # Prepare actual message
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, TO, SUBJECT, TEXT)

    # attempt to send the message
    try:
        server = smtplib.SMTP(config['smtp_server'], 587)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(gmail_user, gmail_pwd)
        server.sendmail(FROM, TO, message)
        server.close()
    except smtplib.SMTPException as e:
        logging.error("Failed to send the alert for {}! Error:\n{}".format(changed_url, e))


def write_hashes(url_hashes):
    """Write the dictionary containing the hashes of both each URL and its contents to a pickle."""
    logging.debug("writing the hashes dictionary as a pickle to the url_hash_record_path")

    with open(config['url_hash_record_path'], 'wb') as output_file:
        pickle.dump(url_hashes, output_file)


def main():
    """Monitor a URL for any changes since the last pass."""
    logging.debug("starting the main function")

    # parse the command line arguments
    init_parser()

    url_change = False

    # get all of the hashes from the previous pass
    previous_hashes = get_previous_hashes()

    # get a list of all urls to be examined
    for site in config['sites']:
        files = config['sites'][site]

        # if there are no files given, monitor the URL
        if len(files) == 0:
            files.append(site)

        for file in files:
            url = site + "/" + file
            # get the content of the URL
            website_text = get_website_text(url)

            # get the hash of each url
            url_hash, website_text_hash = get_hash(url, website_text)

            # if we have the hash for this site already...
            if url_hash in previous_hashes:
                # compare this hash to the previous pass and send an alert if there is a difference
                if (previous_hashes[url_hash] != website_text_hash):
                    # something is different... sound the alarm!
                    send_alert(url, str(datetime.today()))

                    # redifine the hash value for this website's text to be the new hash
                    previous_hashes[url_hash] = website_text_hash
                    url_change = True

            # if we do not have the hash for this site already...
            else:
                # record the value of this new URL
                previous_hashes[url_hash] = website_text_hash
                url_change = True

    # if the hash of write_hashesa URL has been added or changed...
    if url_change:
        # write the new value to a pickle
        write_hashes(previous_hashes)


if __name__ == '__main__':
    # setup logging
    log_format = '%(asctime)s %(levelname)s: %(message)s [%(funcName)s :: %(lineno)d]'
    logging.basicConfig(filename=config['log_file_path'], filemode='w', level=config['logging_level'], format=log_format)

    # record the values of the websites
    main()
