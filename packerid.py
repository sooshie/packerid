#!/usr/local/bin/python
#
# Author: Jim Clausing
# Date:   2009-05-15
# Version: 1.4
# Description: I really like PEiD (http://peid.has.it), but it is
#	Windows only and I haven't been able to get it to just output
#	the packers from the commandline (if it can be done, let me
#	know how), so I wrote this script which uses a PEiD database
#	to identify which packer (if any) is being used by a binary.
#	I wrote this for 3 primary reasons:
#	packer (if any) is being used by a binary.
#	  1) I wanted a command line tool that run on Linux/Unix/OSX
#	  2) I figured it was time to teach myself Python
#	  3) Ero Carrera had done the hard part with pefile :)
#
# Thanx to Ero Carrera for creating peutils and pefile.
# Thanx to BobSoft for his great PEiD database at http://www.secretashell.com/BobSoft/
# Thanx to the authors of PEiD for a really useful tool.useful.
#
# 2007-10-08 - fix a problem where I left out 'print'
# 2007-10-25 - add -V switch to print out version number
# 2009-05-15 - added some error handling as recommended by Joerg Hufschmidt
#
# 2014-12-03 - incremented to 1.5, sig extraction, moved over to Argument Parser and created terse output - sooshie@gmail.com
# 2014-12-05 - disassembly support with capstone-engine.org, 32bit for now. 
#              JSON output, updates to the args for more control over output - sooshie@gmail.com

import pefile
import peutils
import time
import json
import sys
import base64
from capstone import *
from argparse import ArgumentParser

def get_sig(filename, pe, extract):
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    if address == 0:
        return None
    retval = []
    if extract:
        with open(filename + ".der", 'wb+') as out:
            offset = address+8
            out.write(pe.write()[offset:offset+size])
            retval.append("\t{} {} {}.der".format(hex(address), size, filename))
    else:
        retval.append("\t%s %s" %(hex(address), size))
    return retval
    

def main():
    version = "1.5"
    parser = ArgumentParser(description="Used to check PEid databases against files in Python")
    parser.add_argument("-D", "--database",
                        dest="alt_db", help="use alternate signature database DB", metavar="DB")
    parser.add_argument("-J", "--JSON",
                        dest="json_out", help="print terse output as JSON", action="store_true")
    parser.add_argument("-P", "--peid",
                        dest="peid", help="print PEiD matches", action="store_true")
    parser.add_argument("-V", "--version",
                        dest="version", help="show version number", default=False, action="store_true")
    parser.add_argument("-a", "--all",
                        dest="show_all", help="show all PE info", default=False, action="store_true")
    parser.add_argument("-d", "--disasm",
                        dest="disasm", help="disassemble the first X bytes after EP", metavar="X", type=int)
    parser.add_argument("-e", "--extract-sig",
                        dest="extract_sig", help="extracts the digital signature", default=False, action="store_true")
    parser.add_argument("-m", "--all-matches",
                        dest="show_matches", help="show all signature matches", default=False, action="store_true")
    parser.add_argument("-p", "--pretty-print",
                        dest="pretty_print", help="pretty print JSON document", default=False, action="store_true")
    parser.add_argument("-t", "--terse",
                        dest="terse", help="give a short listing of various PE properties", default=False, action="store_true")
    parser.add_argument("files", nargs='+', help='Files to analyze')
    
    args = parser.parse_args()
    
    if args.version:
        print("Packerid.py version ",version,"\n Copyright (c) 2007, Jim Clausing, forked by Sconzo")
        sys.exit(0)

    if args.alt_db and (args.peid | args.show_all | args.show_matches):
        signatures = peutils.SignatureDatabase(args.alt_db)
    elif (args.peid | args.show_all | args.show_matches):
        signatures = peutils.SignatureDatabase('/usr/local/etc/userdb.txt')
    json_out = False
    if args.json_out:
        json_out = True

    file_json = {}
    for file in vars(args)['files']:
        j_output = {}
        try:
            pe = pefile.PE(file)
        except Exception as e:
            sys.stderr.write("[*] Error with %s - %s\n" %(file, str(e)))
            continue
   
        if not args.terse: 
            if args.show_all|args.show_matches:
                matches = signatures.match_all(pe, ep_only = True)
                t = []
                if matches == None or len(matches) == 0:
                    if not json_out: print("None")
                else:
                    t = set()
                    for m in matches:
                        t.add(m[0])
                    if json_out: j_output['PEid'] = t
                    else: print("\t" + ", ".join(t))
            elif args.peid:
                matches = signatures.match(pe, ep_only = True)
                if matches == None:
                    if not json_out: print("None")
                else:
                    if json_out: j_output['PEid'] = matches[0]
                    else: print(matches[0])
    
        if args.show_all:
            print(pe.dump_info())    
        if args.terse:
            if args.peid:
                matches = signatures.match_all(pe, ep_only = True)
                if matches == None or len(matches) == 0:
                    if json_out: j_output['PEiD'] = ["None"]
                    else: print("PEiD\n\tNone")
                else:
                    t = set()
                    for m in matches:
                        t.add(m[0])
                    if json_out: j_output['PEiD'] = t 
                    else: print("PEiD\n\t" + ", ".join(t))
   
            if json_out:
                j_output['Entry Point Address'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                j_output['Image Base Address'] = hex(pe.OPTIONAL_HEADER.ImageBase) 
                j_output['Linker Version'] = {}
                j_output['Linker Version']['Major'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
                j_output['Linker Version']['Minor'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
                j_output['OS Version'] = {}
                j_output['OS Version']['Major'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
                j_output['OS Version']['Minor'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion 
            else:
                print("Entry Point Address\n\t{}".format(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)))
                print("Image Base Address\n\t{}".format(hex(pe.OPTIONAL_HEADER.ImageBase)))
                print("Linker Version\n\t{}.{}".format(pe.OPTIONAL_HEADER.MajorLinkerVersion,pe.OPTIONAL_HEADER.MinorLinkerVersion))
                print("OS Version\n\t{}.{}".format(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))

            if pe.FILE_HEADER.Machine == 0x14c: 
                if json_out: j_output['Machine'] = 'x86'
                else: print("Machine\n\tx86")
            elif pe.FILE_HEADER.Machine == 0x14d:
                if json_out: j_output['Machine'] = '486'
                else: print("Machine\n\t486")
            elif pe.FILE_HEADER.Machine == 0x14e:
                if json_out: j_output['Machine'] = 'Pentium'
                else: print("Machine\n\tPentium")
            elif pe.FILE_HEADER.Machine == 0x0200:
                if json_out: j_output['Machine'] = 'AMD64 only'
                else: print("Machine\n\tAMD64 only\n")
            elif pe.FILE_HEADER.Machine == 0x8664:
                if json_out: j_output['Machine'] = '64b'
                else: print("Machine\n\t64b")
            else:
                if json_out: j_output['Machine'] = 'Unknown'
                else: print("Machine\n\tUnknown")

            try:
               if json_out: j_output['Compile Time'] = "%s UTC" %(time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))) 
               else: print('Compile Time\n\t{} UTC'.format(time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))))
            except ValueError as e:
               if json_out: j_output['Compile Time'] = "Invalid Time{}".format(time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))) 
               else: print('Compile Time\n\tInvalid Time {}'.format(time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))))
            try:
                if json_out: j_output['Checksum'] =  pe.IMAGE_OPTIONAL_HEADER.CheckSum
                else: print("Checksum\t%s" %(pe.IMAGE_OPTIONAL_HEADER.CheckSum))
            except AttributeError as e:
                pass

            if not json_out:
                print("Sections")
            section_info = {}
            for section in pe.sections:
                name = ""
                # occasionally a nul sneaks in, don't print from the nul to eos
                if "\0" in str(section.Name):
                    nul = section.Name.index("\0")
                    name = str(section.Name[:nul])
                if json_out:
                    section_info[name] = {}
                    section_info[name]['VirtualAddress'] = hex(section.VirtualAddress) 
                    section_info[name]['VirtualSize'] = hex(section.Misc_VirtualSize)
                    section_info[name]['RawDataSize'] = hex(section.SizeOfRawData) 
                else: print("\t{} {} {} {}".format(str(name), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData))
            if json_out: j_output['Sections'] = section_info

            if not json_out:
                print("Imports")
            try:
                import_info = {}
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if not json_out: print("\t" + str(entry.dll) )
                    import_info[entry.dll] = {}
                    for imp in entry.imports:
                        if json_out:
                            import_info[entry.dll]['address'] = imp.address
                            if imp.ordinal == None: import_info[entry.dll]['name'] = base64.encodeBase64String(imp.name)
                            else: import_info[entry.dll]['ordinal'] = imp.ordinal
                        else: print('\t\t%s %s' %(hex(imp.address), (imp.name if imp.ordinal == None else "("+str(imp.ordinal)+")")))
                if len(import_info) > 0:
                    j_output['Imports'] = import_info 
            except AttributeError as e:
                if not json_out: print("\tNone")

            if not json_out:
                print("Exports")
            try:
                export_info = {}
                if len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0:
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if json_out:
                            export_info[exp.name] = {}
                            export_info[exp.name]['address'] = hex(exp.address)
                            export_info[exp.name]['ordinal'] = exp.ordinal
                        else: print('\t\t%s %s (%s)' %(hex(exp.address), exp.name, exp.ordinal))
                    j_output['Exports'] = export_info
                else:
                    print("\tNone")
            except AttributeError as e:
                print("\tNone")
            sig_info = get_sig(file, pe, args.extract_sig)
            if sig_info:
                if json_out:
                    j_output['Signature'] = sig_info
                else:
                    print("Digital Signature\n\t%s" + "\n\t".join(sig_info))

            if args.disasm and not json_out:
                print("Dissassembly")

        if args.disasm:
            asm = []
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
            data = pe.get_memory_mapped_image()[ep:ep+args.disasm]
            #
            # Determine if the file is 32bit or 64bit
            #
            mode = CS_MODE_32
            if pe.OPTIONAL_HEADER.Magic == 0x20b:
                mode = CS_MODE_64

            md = Cs(CS_ARCH_X86, mode)
            for (address, size, mnemonic, op_str) in md.disasm_lite(data, 0x1000):
                if json_out: 
                    t = {}
                    t['address'] = address
                    t['mnemonic'] = mnemonic
                    t['op_str'] = op_str
                    asm.append(t)
                else: 
                    if args.terse:
                        print("\t0x{}:\t{}\t{}".format(address, mnemonic, op_str))
                    else:
                        print("0x{}:\t{}\t{}".format(address, mnemonic, op_str))
            if json_out:
                j_output['Disassembly'] = asm

        file_json[file] = j_output

    if json_out:
        if args.pretty_print:
            print(json.dumps(file_json, sort_keys=True, indent=4, separators=(',',': ')))
        else:
            print(json.dumps(file_json, separators=(',',':')))

    return

if __name__ == "__main__":
    main()
