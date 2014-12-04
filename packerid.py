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

import pefile
import peutils
import time
import sys
from argparse import ArgumentParser

def get_sig(filename, pe, extract):
    print "Digital Signature"
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print "\tNone"
        return

    if extract:
        with open(filename + ".der", 'wb+') as out:
            offset = address+8
            out.write(pe.write()[offset:offset+size])
            print "\t%s %s %s.der" %(hex(address), size, filename)
    else:
        print "\t%s %s" %(hex(address), size)

def main():
    version = "1.5"
    parser = ArgumentParser(description="Used to check PEid databases against files in Python")
    parser.add_argument("-a", "--all",
                        dest="show_all", help="show all PE info", default=False, action="store_true")
    parser.add_argument("-D", "--database",
                        dest="alt_db", help="use alternate signature database DB", metavar="DB")
    parser.add_argument("-m", "--all-matches",
                        dest="show_matches", help="show all signature matches", default=False, action="store_true")
    parser.add_argument("-t", "--terse",
                        dest="terse", help="give a short listing of various PE properties", default=False, action="store_true")
    parser.add_argument("-V", "--version",
                        dest="version", help="show version number", default=False, action="store_true")
    parser.add_argument("-e" "--extract-sig",
                        dest="extract_sig", help="extracts the digital signature", default=False, action="store_true")
    parser.add_argument("files", nargs='+', help='Files to analyze')
    
    args = parser.parse_args()
    
    if args.version:
        print "Packerid.py version ",version,"\n Copyright (c) 2007, Jim Clausing, forked by Sconzo"
        sys.exit(0)
    
    if args.alt_db:
        signatures = peutils.SignatureDatabase(args.alt_db)
    else:
        signatures = peutils.SignatureDatabase('/usr/local/etc/userdb.txt')
    
    for file in vars(args)['files']:
        try:
            pe = pefile.PE(file)
        except Exception as e:
            print "[*] Error with %s - %s" %(file, str(e))
            continue
    
        if args.show_all|args.show_matches:
            matches = signatures.match_all(pe, ep_only = True)
            t = []
            if matches == None or len(matches) == 0:
                print "\tNone"
            else:
                t = set()
                for m in matches:
                    t.add(m[0])
                print "\t" + ", ".join(t)
        elif not args.terse:
            matches = signatures.match(pe, ep_only = True)
            if matches == None:
                print "\tNone"
            else:
                print matches[0]
    
        if args.show_all:
            print pe.dump_info()
    
        if args.terse:
            print "PEid"
            matches = signatures.match_all(pe, ep_only = True)
            if matches == None or len(matches) == 0:
                print "\tNone"
            else:
                t = set()
                for m in matches:
                    t.add(m[0])
                print "\t" + ", ".join(t)
    
            print "Entry Point Address\n\t%s" %(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
            print "Image Base Address\n\t%s" %(hex(pe.OPTIONAL_HEADER.ImageBase))
            print "Linker Version\n\t%d.%d" %(pe.OPTIONAL_HEADER.MajorLinkerVersion,pe.OPTIONAL_HEADER.MinorLinkerVersion)
            print "OS Version\n\t%d.%d" %(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
            print "Machine"
            if pe.FILE_HEADER.Machine == 0x14c: print "\tx86"
            elif pe.FILE_HEADER.Machine == 0x14d: print "\t486"
            elif pe.FILE_HEADER.Machine == 0x14e: print "\tPentium"
            elif pe.FILE_HEADER.Machine == 0x0200: print "\tAMD64 only"
            elif pe.FILE_HEADER.Machine == 0x8664: print "\t64b"
            else: print "Unknown"
            try:
                print 'Compile Time\n\t%s UTC' %(time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp)))
            except ValueError, e:
                print "Compile Time\n\tInvalid Time"
            print "CheckSum"
            try:
                print "\t%s" %(pe.IMAGE_OPTIONAL_HEADER.CheckSum)
            except AttributeError as e:
                print "\tNone"
            print "Sections"
            for section in pe.sections:
                name = ""
                # occasionally a nul sneaks in, don't print from the nul to eos
                if "\0" in section.Name:
                    nul = section.Name.index("\0")
                    name = section.Name[:nul]
                print "\t%s %s %s %s" %(name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData )
            print "Imports"
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    print "\t" + entry.dll
                    for imp in entry.imports:
                        print '\t\t%s %s' %(hex(imp.address), (imp.name if imp.ordinal == None else "("+str(imp.ordinal)+")"))
            except AttributeError as e:
                print "\tNone"
            print "Exports"
            try:
                if len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0:
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        print '\t\t%s %s (%s)' %(hex(exp.address), exp.name, exp.ordinal)
                else:
                    print "\tNone"
            except AttributeError as e:
                print "\tNone"
            get_sig(file, pe, args.extract_sig)
        return

if __name__ == "__main__":
    main()
