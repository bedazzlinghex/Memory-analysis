#!/usr/bin/python
'''
Author: Stian Svendsen
Email: stian.l.svendsen@gmail.com
Date: 2018-04-18
API_VERSION: 1.1
PROGRAM_VERSION: 1.2

Requirements:
    * sudo pip install prettytable
    * install the irmacl 1.1 api client from: https://github.com/quarkslab/irma-cli/tree/v1.1

Version 1.2 features:
    * Tweaked the code to be more robust hopefully prettier than it was
    * All helper functions are now in a seperate class
    * Fixed a bug where a user was trying to add a tag to a file, where the tag already was present in that file.

Version 1.1 features:
    * Added download feature
    * Added manual single tagging of one file
    * Added manual mass tagging based on returned search results
    * Added possibility to add tag to files submitted via the vol_analysis script
    * Few tweaks in the code to be more bulletproof

Vesion 1.0 features:
    * Query IRMA for a file by name or any hash supported by IRMA
    * Submit a single file on the command line to IRMA
    * Submit all files in a directory either on the command line or included in a other script
    * List all available probes

Version 1.1 bugs:
    * Adding an exsisting tag to a file results in an error

Version 1.0 bugs:
    None known at this point

doc_sources:
https://irma.readthedocs.io/en/latest/faq/swagger.html
https://github.com/quarkslab/irma-cli/tree/v1.1
'''
from irmacl.helpers import *
import sys
import re
import os
from prettytable import PrettyTable
import argparse
import json
from bedazzlinghexlib import irma_helpers

def main(argv):
    parser = argparse.ArgumentParser(description='Query your IRMA for previous scans or submit new files to be scanned.',add_help=True, prog='Irma_API', version='1.2')

    #Arguments
    parser.add_argument('-V','--verbose', action='store_true', default=False, help='Turn verbose mode on')
    parser.add_argument('-i','--ifile', metavar=('inputfile'))
    parser.add_argument('-s','--search', type=str,metavar=('value'))
    parser.add_argument('-r','--recursive',nargs='+',help='Recursive submission of files with optional tagging',metavar=('dir', 'tag'))
    parser.add_argument('-p','--probes', action="store_true", help='List available AVs')
    parser.add_argument('-d','--download',type=str, nargs=2,metavar=('sha256','output_filename'))
    parser.add_argument('-t', '--tag', nargs=2, metavar=('sha256','tag'))
    parser.add_argument('-m', '--multitag', action="store_true", help='Tag multiple files based on search')
    args = parser.parse_args()

    #Submit file
    if args.ifile:
        scan(args.ifile)

    #Search
    elif args.search:
        search_hash(args.search)

    #List probes
    elif args.probes:
        list_probes()

    #Resursive submission of dir
    elif args.recursive:
        for root, dirs, files in os.walk(args.recursive[0]):
            for file in files:
                filepath = os.path.join(os.path.abspath(root), file)
                #Add tags to the file submitted
                if len(args.recursive) == 2:
                    scan(filepath,args.recursive[1])
                else:
                    scan(filepath)

    #download a file
    elif args.download:
        sha256 = args.download[0]
        dst_path = args.download[1]
        download_file(sha256,dst_path)

    #add tag
    elif args.tag:
        sha256 = args.tag[0]
        tag = args.tag[1]
        add_tag(sha256,tag)

    #Mass tagging
    elif args.multitag:
        add_multiple_tags()


#Add tags to multiple files at the same time manually
def add_multiple_tags():
    table = stian.table_generator(2)

    search_term = raw_input('Enter search term: ')
    result = stian.add_tags_to_hash(search_term)
    hashes = []
    for filename,sha256 in result.iteritems():
        table.add_row([filename,sha256])
        hashes.append(sha256)
    print table
    unique = list(set(hashes)) #Deduplicate hash list

    proceed = raw_input('Do you wish to add a tag to these results (Y/n): ') or "y"
    if proceed == 'y':
        tag = raw_input('Enter tag: ')
        for item in unique:
            add_tag(item,tag)
    else:
        sys.exit(1)



def add_tag(sha256,tag):
    taglist = irma_helpers.update_tag_list()
    tags = []

    for key, value in taglist.iteritems():
        tags.append(value)

    #Check if tag already in taglist from irma
    if tag in tags:
        _id = irma_helpers.find_id_from_tag(tag)

        #Fetch the resultID for the file submitted
        resultid = irma_helpers.fetch_resultid(sha256)
        for f in resultid:
            #Gather the existing tags for that file
            exsisting_tags = irma_helpers.fetch_tag(f)

            if tag not in exsisting_tags:
                #add tag if it is not present
                file_tag_add(sha256, _id, verbose=False)
    else:
        tag_new(tag,verbose=False) #create new tag
        new_id = find_id_from_tag(tag)
        file_tag_add(sha256, new_id, verbose=False)



def scan(arg,tag=None):
    scan = scan_files([arg], force=False, resubmit_files=False, blocking=True, post_max_size_M=30)
    table = irma_helpers.table_generator(3)
    table.add_row([scan.results[0].name,scan.results[0].file_sha256,scan.results[0].probes_total,scan.results[0].probes_finished,scan.results[0].scan_date,scan.results[0].status,scan.results[0].result_id])

    print table
    if tag == None:
        print "No tag specified, continue"
    else:
        add_tag(scan.results[0].file_sha256,tag)



def search_hash(arg):
    table = irma_helpers.table_generator(1)
    if irma_helpers.check_valid_hash(arg) == True:
        result = file_search(hash=arg)
        (total, res) = result
        for item in res:
            tag = irma_helpers.fetch_tag(item.result_id)
            pdate_first_scan = irma_helpers.fetch_date(item.result_id)
            table.add_row([item.name,item.file_sha256,item.probes_total,item.probes_finished,pdate_first_scan, item.status,', '.join(tag)])
        print table

    else:
        result = file_search(name=arg,limit=None)
        (total, res) = result
        for item in res:
            tag = irma_helpers.fetch_tag(item.result_id)
            pdate_first_scan = irma_helpers.fetch_date(item.result_id)
            table.add_row([item.name,item.file_sha256,item.probes_total,item.probes_finished,pdate_first_scan,item.status,', '.join(tag)])
        print table



def list_probes():
    probes = probe_list(verbose=False)
    print json.dumps(probes,indent=4, sort_keys=True)



def download_file(sha256,dst_path):
    dl = file_download(sha256,dst.path,verbose=False)

if __name__ == "__main__":
    main(sys.argv[1:])
