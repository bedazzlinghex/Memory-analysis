#!/usr/bin/python
'''
Author: Stian
Email: stian.l.svendsen@gmail.com
Date: 2018-04-18
API_VERSION: 1.1
PROGRAM_VERSION: 1.2

Helper library for IRMA api, belongs to irma.py.

'''

from irmacl.helpers import *
import re
from prettytable import PrettyTable

class irma_helpers(object):


    _HEADER=['Name', 'SHA256','Probes total','Probes finished','Scan Date','Status','Tag']
    _HEADER2=['Filename', 'SHA256']
    _HEADER3=['Name', 'SHA256','Probes total','Probes finished','Scan Date','Status','Result ID']

    @staticmethod
    def find_id_from_tag(tag):
        for key,value in irma_helpers.update_tag_list().iteritems():
            if tag == value:
                return key
        return None

    @staticmethod
    def update_tag_list():
        taglist = tag_list(verbose=False)
        tags = {}
        for x in taglist:
            tags[x.id] = x.text.encode('ascii')
        return tags

    @staticmethod
    def fetch_tag(resultid):
        result = scan_proberesults(resultid)
        tags = result.file_infos.tags
        index = 0
        taglist = []
        for item in tags:
            value = tags[index].text
            taglist.append(value)
            index = index+1
        return taglist

    @staticmethod
    def fetch_date(resultid):
        result = scan_proberesults(resultid)
        return result.file_infos.pdate_last_scan

    @staticmethod
    def fetch_size(resultid):
        result = scan_proberesults(resultid)
        size = result.file_infos.size
        return size

    @staticmethod
    def fetch_resultid(sha256):
        result = file_search(hash=sha256)
        (total, res) = result
        resultid = []
        for item in res:
            resultid.append(item.result_id)
        return resultid

    @staticmethod
    def check_valid_hash(hashes):
        result_md5 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', hashes)
        result_sha1 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', hashes)
        result_sha256 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', hashes)

        if result_md5 or result_sha1 or result_sha256:
            return True
        else:
            return False

    @staticmethod
    def table_generator(header_choice):
        if header_choice == 1:
            table = PrettyTable(field_names=irma_helpers._HEADER,header_style='upper',padding_width=1)
            table.align['Tag'] = 'l'
            table.align['Name'] = 'l'
            return table
        elif header_choice == 2:
            table = PrettyTable(field_names=irma_helpers._HEADER2,header_style='upper',padding_width=1)
            table.align['Filename'] = 'l'
            return table
        elif header_choice == 3:
            table = PrettyTable(field_names=irma_helpers._HEADER3,header_style='upper',padding_width=1)
            table.align['Name'] = 'l'
            return table
        else:
            print "Invalid header choice"

    @staticmethod
    def add_tags_to_hash(search_term):
        value = {}
        if irma_helpers.check_valid_hash(search_term) == True:
            result = file_search(hash=search_term,limit=None)
            (total,res) = result
            for item in res:
                value[item.name] = item.file_sha256.encode('ascii')
            return value
        else:
            result = file_search(name=search_term,limit=None)
            (total,res) = result
            for item in res:
                value[item.name] = item.file_sha256.encode('ascii')
            return value
