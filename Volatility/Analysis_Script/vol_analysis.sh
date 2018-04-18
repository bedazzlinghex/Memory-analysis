#!/bin/sh
'''
Author: Bedazzlinghex
Date: 2018-04-18
Version 1.0

Use as you want!

This script is currently setup to use my api interaction script with IRMA to submit files carved out from a memory dump. Comment that out
if you do not want to use this feature. Read through the script before you use it! some fetaures requires your customizing.

'''
OPTIND=1

profile=""
output_dir=""
memdump=""
tag=""

vol_path='python /path/to/vol.py' #Change to your vol path
strings_path='/usr/bin/strings'
python_path='/usr/bin/python' #Change to your python2.7 path

while getopts "p:d:f:t:" opt; do
  case $opt in
    p)
      echo "PROFILE set to: $OPTARG" >&2
      profile=$OPTARG #Sets the profile
      ;;
    d)
      echo "output directory set to: $OPTARG" >&2
      output_dir=$OPTARG
      ;;
    f)
      echo "Memdump set to: $OPTARG" >&2
      memdump=$OPTARG
      ;;
    t)
      echo "Tag for Irma submission set to: $OPTARG" >&2
      tag=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      echo "Usage: vol_analysis -p Win7SP1x86 -d output_dir -f memdump.raw [-t][tag]"
      exit 1
      ;;
    :)
      echo "Option -$OPTARG reqires an argument." >&2
      exit 1
      ;;
  esac
done


#Create directories that we need....
#--------------------------------------
if [ ! -d $output_dir/malfind ]; then
  mkdir -p $output_dir/malfind;
fi

if [ ! -d $output_dir/triage ]; then
  mkdir -p $output_dir/triage;
fi

if [ ! -d $output_dir/malware_scans ]; then
  mkdir -p $output_dir/malware_scans;
fi

if [ ! -d $output_dir/registry_hives ]; then
  mkdir -p $output_dir/registry_hives;
fi

standard ()
{
  #Vol plugins
  #----------------
  $vol_path --profile=$profile -f $memdump pslist --output-file=$output_dir/pslist.txt
  $vol_path --profile=$profile -f $memdump pstree --output-file=$output_dir/pstree.txt
  $vol_path --profile=$profile -f $memdump psxview --apply-rules --output-file=$output_dir/psxview.txt
  $vol_path --profile=$profile -f $memdump systeminfo --output-file=$output_dir/systeminfo.txt
  $vol_path --profile=$profile -f $memdump malfind --output-file=$output_dir/malfind.txt
  $vol_path --profile=$profile -f $memdump autoruns --output-file=$output_dir/autoruns.txt
  $vol_path --profile=$profile -f $memdump hollowfind --output-file=$output_dir/hollowfind.txt
  $vol_path --profile=$profile -f $memdump consoles --output-file=$output_dir/consoles.txt
  $vol_path --profile=$profile -f $memdump cmdscan --output-file=$output_dir/cmdscan.txt
  $vol_path --profile=$profile -f $memdump dlllist --output-file=$output_dir/dlllist.txt
  $vol_path --profile=$profile -f $memdump ldrmodules --verbose --output-file=$output_dir/ldrmodules.txt
  $vol_path --profile=$profile -f $memdump schtasks --output-file=$output_dir/schtasks.txt
  $vol_path --profile=$profile -f $memdump mimikatz --output-file=$output_dir/mimikatz.txt
  $vol_path --profile=$profile -f $memdump malsysproc --output-file=$output_dir/malsysproc.txt
  $vol_path --profile=$profile -f $memdump privs --silent --output-file=$output_dir/privileges.txt
  grep "Command line" $output_dir/dlllist.txt > $output_dir/commandline_arguments_from_procs.txt
  $vol_path --profile=$profile -f $memdump shimcache --output-file=$output_dir/shimcache.txt
  $vol_path --profile=$profile -f $memdump pdblist --renamed_only --output-file=$output_dir/pdblist.txt
  $vol_path --profile=$profile -f $memdump filescan --output-file=$output_dir/filescan.txt
  $vol_path --profile=$profile -f $memdump handles --output-file=$output_dir/handles.txt
  $vol_path --profile=$profile -f $memdump printkey -K "ControlSet001\\Services" --output-file=$output_dir/all_services_from_registry.txt
  $vol_path --profile=$profile -f $memdump svcscan --verbose --output-file=$output_dir/svcscan.txt
  $vol_path --profile=$profile -f $memdump browserhooks --output-file=$output_dir/browserhooks.txt
  $vol_path --profile=$profile -f $memdump logfile > $output_dir/logfile_tmp
  grep -v "NO FILENAME FOUND" $output_dir/logfile_tmp > logfile.txt
  rm $output_dir/logfile_tmp
}

lateral_movement ()
{
  grep -i -f /usr/local/bin/common_search_strings.txt $output_dir/vol_strings.txt > $output_dir/search_for_lateral_movement.txt

}

submit_to_irma ()
{
    echo $output_dir
    $python_path /usr/local/bin/irma_dev.py --recursive $output_dir/test_dir/ $tag

}

bad_kernel_drivers ()
{
  cut -d " " -f 2 $output_dir/kernel_modules.txt > $output_dir/tmp99.txt
  sed -e 's/--------------------//g' $output_dir/tmp99.txt > $output_dir/tmp101.txt
  sort -u $output_dir/tmp101.txt > $output_dir/kernel_modules_sorted.txt
  rm $output_dir/tmp99.txt
  rm $output_dir/tmp101.txt
  match=`cat $output_dir/kernel_modules_sorted.txt | awk -F. '{print $1}'| tr -d ' ' | tr -d '\t' | tr '\n' '|'`;   egrep "^\"(no_such_driver${match})\"" /usr/local/bin/drv_list.txt > $output_dir/search_for_bad_kernel_drivers.txt
  rm $output_dir/kernel_modules_sorted.txt

}

winxp_net ()
{
  $vol_path --profile=$profile -f $memdump netconn --output-file=$output_dir/netconn.txt
  $vol_path --profile=$profile -f $memdump sockets --output-file=$output_dir/sockets.txt
}

vistapluss_net ()
{
  $vol_path --profile=$profile -f $memdump netscan --output-file=$output_dir/netscan.txt
}

malware ()
{

  $vol_path --profile=$profile -f $memdump dyrescan --output-file=$output_dir/malware_scans/malware_dyrescan.txt
  $vol_path --profile=$profile -f $memdump ghostrat --output-file=$output_dir/malware_scans/malware_ghostrat.txt
  $vol_path --profile=$profile -f $memdump apt17scan --output-file=$output_dir/malware_scans/apt17scan.txt
  $vol_path --profile=$profile -f $memdump plugxscan --output-file=$output_dir/malware_scans/malware_plugxscan.txt
  $vol_path --profile=$profile -f $memdump findbadvad --output-file=$output_dir/malware_scans/findbadvad.txt
  $vol_path --profile=$profile -f $memdump redleavesscan --output-file=$output_dir/malware_scans/malware_redleavesscan.txt
}

systemprocs ()
{
  #Look for system processes
    #lsm.exe - 1 instance
    #csrss.exe - two or more instances (for session 0 and 1)
    #lsass.exe - 1 instance
    #svchost.exe - Always services.exe as the parent process
    #winlogon - 1 for each user logon.
    #smss.exe - One master instance and another child instance per session. Children exit after creating their session.
    #system - one(1) at boot time.
  egrep -i '(svchost|lsass|csrss|smss|services.exe|wininit.exe|lsm|winlogon|system)' $output_dir/pslist.txt > $output_dir/system_procs.txt
}

kernel ()
{
  #Kernel
  $vol_path --profile=$profile -f $memdump modules --output-file=$output_dir/kernel_modules.txt
  $vol_path --profile=$profile -f $memdump ssdt --output-file=$output_dir/kernel_ssdt.txt
  $vol_path --profile=$profile -f $memdump drivermodule --output-file=$output_dir/kernel_drivermodule.txt
  $vol_path --profile=$profile -f $memdump unloadedmodules --output-file=$output_dir/kernel_unloaded_modules.txt
  $vol_path --profile=$profile -f $memdump timers --output-file=$output_dir/kernel_timers.txt
  $vol_path --profile=$profile -f $memdump driverirp --output-file=$output_dir/kernel_driverIRP.txt
  $vol_path --profile=$profile -f $memdump callbacks --output-file=$output_dir/callbacks.txt
  egrep -v "(win32k.sys|ntoskrnl.exe)" $output_dir/kernel_ssdt > $output_dir/ssdt_check.txt

}

#Strings
#------------
strings ()
{
$strings_path -a -td $memdump > $output_dir/tmp.txt
$strings_path -a -el -td $memdump >> $output_dir/tmp.txt
$vol_path --profile=$profile -f $memdump strings -s $output_dir/tmp.txt -S --output-file=$output_dir/vol_strings.txt
rm $output_dir/tmp.txt
}

timeline ()
{
  #Timeline
  #------------
  $vol_path --profile=$profile -f $memdump timeliner --output=body --output-file=$output_dir/body_temp.txt
  $vol_path --profile=$profile -f $memdump mftparser --output=body >> $output_dir/body_temp.txt
  $vol_path --profile=$profile -f $memdump shellbags --output=body >> $output_dir/body_temp.txt
  mactime -b $output_dir/body_temp.txt -d > $output_dir/timeliner.txt
  rm $output_dir/body_temp.txt
}

triage ()
{
  #Triage
  #-------------
  $vol_path --profile=$profile -f $memdump procdump -D $output_dir/triage
  $vol_path --profile=$profile -f $memdump malfind -D $output_dir/malfind
  $vol_path --profile=$profile -f $memdump moddump -D $output_dir/triage
  $vol_path --profile=$profile -f $memdump dlldump -D $output_dir/triage
  $vol_path --profile=$profile -f $memdump dumpfiles --name --summary-file=$output_dir/dumpfiles_summary.json --ignore-case --regex "\.(exe|dll|sys|bat|ps1)$" -D $output_dir/triage
  $python_path /usr/local/bin/parsesummary.py $output_dir/dumpfiles_summary.json > $output_dir/dumpfiles_summary_parsed.json
  rm $output_dir/dumpfiles_summary.json
  $vol_path --profile=$profile -f $memdump dumpfiles --name --ignore-case --regex "system32.config.(sam|software|system)$" -D $output_dir/registry_hives
}

#Change to your index.yar location
yara ()
{
  #Yarascan
  #-------------
  $vol_path --profile=$profile -f $memdump yarascan --max-size=5000000 --size=64 --all -y /path/to/index.yar --output-file=$output_dir/yarascan.txt
}


av ()
{
  #antivirus
  clamscan -i --max-filesize=5000000 -r $output_dir/triage > $output_dir/clamscan_results_triage.txt
  clamscan -i --max-filesize=5000000 -r $output_dir/malfind > $output_dir/clamscan_results_malfind.txt
}

#Clean up empty files
cleanup ()
{
  find $output_dir/*.txt -type f -size 0 -delete
}

#networkpackets ()
#{
  #Extract network packets
  #------------------------
  #bulk_extractor -x all -e net -o $output_dir $memdump
  #bulk_extractor -x all -e winpe -e winprefetch -e windirs -o $output_dir/bulk_extractor $memdump
#}


case $profile in
  Win2012R2x64)
    echo "Win2012 detected, not able to use the vad plugins such as plugx, do this manually."
    standard
    vistapluss_net
    systemprocs
    kernel
    bad_kernel_drivers
    lateral_movement
    triage
    av
    yara
    timeline
    strings
    cleanup
    submit_to_irma
    ;;
  Win2003*)
    echo "Win2003 detected, running 2003 plugins"
    standard
    winxp_net
    systemprocs
    malware
    kernel
    bad_kernel_drivers
    lateral_movement
    triage
    yara
    av
    timeline
    strings
    cleanup
    submit_to_irma
    ;;
  WinXP*)
    echo "WinXP detected, running XP plugins"
    standard
    winxp_net
    malware
    systemprocs
    kernel
    bad_kernel_drivers
    lateral_movement
    triage
    yara
    av
    strings
    timeline
    cleanup
    submit_to_irma
    ;;
  *)
    echo "Running all plugins"
    standard
    malware
    systemprocs
    vistapluss_net
    kernel
    lateral_movement
    bad_kernel_drivers
    triage
    yara
    av
    timeline
    strings
    cleanup
    submit_to_irma
    ;;
esac

