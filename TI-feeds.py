import shutil
import datetime
import re
import argparse
import requests
import zipfile
import xml.etree.ElementTree as etree
import csv
import sys
import os
import logging
# from requests.auth import HTTPBasicAuth
from io import BytesIO


# LOGGING
logger = logging.getLogger('TI-Feeds')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('TI-Feeds.log')
fh.setLevel(logging.DEBUG)
log_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
fh.setFormatter(log_format)
logger.addHandler(fh)


class Feed:
    def __init__(self, feedtype, feedpath):
        self.feedtype = feedtype
        self.feedpath = feedpath

    def download(self):
        link = "https://xxxxxxxxxxxxxx" + self.feedpath + "?l=1&token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        logger.debug(f"Getting data from {link}")
        try:
            request = requests.get(link)
            # request = requests.get(link + self.feedpath, auth=HTTPBasicAuth(login, passw))
            if not request.ok:
                logger.critical(f"Could not get data from: {link}")
                sys.exit()
        except (requests.ConnectionError, requests.Timeout):
            logger.critical("Couldn't get the data, quitting")
            sys.exit()
        return request

    @staticmethod
    def unzip(request):
        logger.debug(f"unpacking and getting ready for the XML {request}")
        try:
            zip_content = request.content
            zip_response = (zipfile.ZipFile(BytesIO(zip_content)))
            zip_path = zip_response.namelist()[0]
            zip_response.extractall(path=output)
            xmlpath = output + zip_path
            xmlparse = etree.parse(xmlpath)
            xmlroot = xmlparse.getroot()
        except PermissionError:
            logger.critical(f"No rights to folder: {output} . Quitting.")
            sys.exit()
        return xmlroot

    @staticmethod
    def parse(xmlroot, filename, xml_node, xml_attrib):
        logger.debug(f"parsing XML {xmlroot, filename, xml_node, xml_attrib}")
        feed_list = []

        def address():
            if (nested.attrib[xml_attrib] + "\n") not in feed_list and rg.search(nested.attrib[xml_attrib]):
                feed_list.append(nested.attrib[xml_attrib] + "\n")

        def others():
            if (nested.attrib[xml_attrib] + "\n") not in feed_list:
                feed_list.append(nested.attrib[xml_attrib] + "\n")

        parse_options = [address, others]

        with open(output + filename, "w") as file:
            for nested in xmlroot.iter(xml_node):
                if xml_node == "botnet" and xml_attrib == "address":
                    parse_options[0]()
                else:
                    parse_options[1]()
            feed_list_sorted = sorted(feed_list)
            file.writelines(feed_list_sorted)
        return

    @staticmethod
    def parse_to_csv(xmlroot, filename, xml_iter):
        logger.debug(f"parsing for csv {xmlroot, filename, xml_iter}")
        headerlist = []
        headers = []

        with open(output + filename, "w") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)

            for nested in xmlroot.iter('*'):
                if nested.attrib.keys() not in headerlist:
                    headerlist.append(nested.attrib.keys())

            for key in headerlist:
                for header in key:
                    if header not in headers:
                        headers.append(header)

            writer.writeheader()

            for parent in xmlroot.iter(xml_iter):
                writer.writerow(parent.attrib)
                for child in parent:
                    writer.writerow(child.attrib)
        return

    def parse_url(self, filename, request):
        logger.debug(f"parsing URL {filename, request}")
        feed_list = []

        with open(output + filename, "w") as file:
            for line in request.text.splitlines():
                if not line.startswith("#"):
                    url_splitted = line.split("|")
                    if self.feedtype == "phishing":
                        file.writelines(url_splitted[2] + "\n")
                    elif self.feedtype == "malware":
                        if (url_splitted[4] + "\n") not in feed_list:
                            file.writelines(url_splitted[4] + "\n")
        return


def feed_compare_add_old(filename):
    logger.debug(f"Save old data to compare with the upcoming and show differences {filename}")
    try:
        os.mkdir(temp)
    except FileExistsError:
        logging.info(f"{temp} already exists")
        pass

    try:
        with open(output + filename) as fr, open(temp + filename, "w") as fw:
            for line in fr:
                fw.writelines(line)
    except FileNotFoundError:
        logging.info(f"No such {filename}")
        pass
    return


# compare old feeds with new and save diff
def feed_compare():
    logger.debug("# compare old feeds with new and save diff")
    for file in os.listdir(temp):
        with open(temp + file) as old_fr, open(output + file) as new_fr, open(output + "diff-" + file, "w") as diff_f:
            diff = set(new_fr).difference(old_fr)
            for line in diff:
                diff_f.writelines(line)
    return


feed_files = {
                "contr_addr": "TI-controllers-address.txt",
                "contr_IP": "TI-controllers-IP.txt",
                "contr_url": "TI-controllers-url.txt",
                "contr_csv": "TI-controllers.csv",
                "url_mal": "TI-URL-malware.txt",
                "url_phish": "TI-URL-phishing.txt",
            }

# REGEX
re1 = '(.*)'   # Any Character
re2 = '(.)'	    # Dot
re3 = '([a-z])'   # Any Single Word Character (Not Whitespace)

rg = re.compile(re1+re2+re3, re.IGNORECASE | re.DOTALL)

# Parse arguments
argp = argparse.ArgumentParser()
argp.add_argument("-o", metavar="FOLDER", help="destination folder e.g. /nfs/scripts")
args = argp.parse_args()

try:
    output = args.o + "/output/"
    archive = args.o + "/archive/" + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    temp = args.o + "/temp/"
except TypeError:
    output = os.getcwd() + "/output/"
    archive = os.getcwd() + "/archive/" + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    temp = os.getcwd() + "/temp/"

# Read the old file and compare them with new data
for value in feed_files.values():
    feed_compare_add_old(value)

# move old files
try:
    logger.debug(f"moving files from {output} to {archive}")
    shutil.move(output, archive)
except FileNotFoundError:
    pass

# CONTROLLERS FEED #
contr = Feed("contr", "controllerszip/controllers.xml.zip")
rcontr = contr.download()
xmlroot = contr.unzip(rcontr)
contr.parse(xmlroot, feed_files["contr_addr"], "botnet", "address")
contr.parse(xmlroot, feed_files["contr_IP"], "controller", "ip")
contr.parse(xmlroot, feed_files["contr_url"], "http", "url")
contr.parse_to_csv(xmlroot, feed_files["contr_csv"], "botnet")

# URL MALWARE FEED #
mal = Feed("malware", "malwareurl.txt")
rmal = mal.download()
mal.parse_url(feed_files["url_mal"], rmal)

# URL PHISHING FEED #
phish = Feed("phishing", "phishing_last.txt")
rphish = phish.download()
phish.parse_url(feed_files["url_phish"], rphish)

# comparing old and new feed files
feed_compare()
