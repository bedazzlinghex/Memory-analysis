# Memory-analysis
Contains tools to perform malware and forensic analysis in Memory.

Plugins:
-----------
* Dyrescan.py - parses Dyreconfig in memory.
* Rat9002.py - parses 9002 rat config in memory.
* plugx.py - parses plugx config in memory (modified to also parse config size: 0x170c).
* ghostrat.py - parses ghostrat config in memory.

Analysis_Script:
----------------
* vol_analysis.sh - script to automate analysis with volatility
* common_search_strings.txt - textfile used by vol_analysis.sh to search for common commands used by threat actors. Fill out with your own terms.
* drv_list.txt - List gathered from the Internet with all known bad and good drivernames. Used by vol_analysis.sh to search for bad drivers.

Irma:
---------
* Created a python script to interact with IRMA on a localmachine. This script is also used by vol_analysis.sh to submit and scan all files
  extracted from a memory dump and perform analysis on them with various AV-engines. 
* Usage with vol_analysis script: vol_analysis.sh -p WinXPSP2x86 -f memdump.mem -d /output_path -t CASENAME
** Requires IRMA up and running on your machine and the IRMACL API installed. 
