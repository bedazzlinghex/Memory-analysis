'''
Author: Stian Svendsen
Version 1.0

Based on examples in: The art of memory forensics

Plugin to check for suspicious sections in the virtual address descriptors.
Check wether the CommitCharge is higher that 30 and that the permissions is set to read write execute.
Many types of malware will commit pages they need up front, e.g. poison ivy and PlugX, and they need the
right permissions to execute their code.
'''

import volatility.utils as utils
import volatility.plugins.common as common
import volatility.win32 as win32
import re

class findbadmz(common.AbstractWindowsCommand):
    """Searches for MZ in vad segments with protection 6"""

    def calculate(self):
        addr_space=utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        return tasks

    def render_text(self, outfd, data):
        delim = '-' * 100
        outfd.write('{0}\n'.format(delim))

        for task in data:
            process_space=task.get_process_address_space()
            for vad in task.VadRoot.traverse():
                if vad.u.VadFlags.Protection.v() == 6:
                    data = process_space.read(vad.Start, 1024)
                    if data:
                        found = re.search('4D5A9000', data)
                        if found != -1:
                            print "Found MZ in VAD at: ", hex(vad.Start), hex(vad.End), task.ImageFileName


class findbadvad(common.AbstractWindowsCommand):
    """Searches for suspicious sections in memory"""

    @staticmethod
    def get_vad_base(task, address):
        for vad in task.VadRoot.traverse():
            if vad.End > address >= vad.Start:
                return vad.Start

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        return tasks


    def render_text(self, outfd, data):
	self.table_header(outfd, [("VadStart", "15"), ("VadEnd","15"), ("PID","5"), ("Pname","15"), ("Flags","70"), ("Offset","10")])
        comment = "suspicious"


        for task in data:
            process_space = task.get_process_address_space()
            for vad in task.VadRoot.traverse():
                data = process_space.read(vad.Start, 256) #read in 256 bytes from vad start
                if vad.u.VadFlags.CommitCharge.v() > 8:
                    if vad.Tag == "VadS": #look for small vad segments only
                        if vad.u.VadFlags.Protection.v() == 6:
                            self.table_row(outfd, hex(vad.Start), hex(vad.End), task.UniqueProcessId,task.ImageFileName, str(vad.VadFlags), hex(vad.obj_offset))




'''
Class to detect the standard handles for a CMD.exe process. Look for \Device\Afd\NamedPipe in the handles if the output is not standard. This
could indicate backchannel traffic through cmd.exe via netcat or similar tools.
'''
class findbadcmd(common.AbstractWindowsCommand):
    """Outputs the Standard handles for CMD.exe processes"""

    #StdInput, StdOutput, StdError
    def render_text(self, outfd, data):
        print "Normal behaviour is: 0x3L 0x7L 0xbL"
        delim = '-' * 80
        outfd.write('{0}\n'.format(delim))
        addr_space = utils.load_as(self._config)

        for proc in win32.tasks.pslist(addr_space):
            if str(proc.ImageFileName) != "cmd.exe":
                continue
            if proc.Peb:
                print proc.UniqueProcessId, \
                        hex(proc.Peb.ProcessParameters.StandardInput), \
                        hex(proc.Peb.ProcessParameters.StandardOutput), \
                        hex(proc.Peb.ProcessParameters.StandardError)

