# xref_parser.py
#
# An IDAPython script for parsing call data generated using a 
# corresponding pin tool (xref_finder.dll)
# 
# Author: bNull

from idaapi import *

def image_range():
    """
    Return an integer representing the largest possible address in the
    binary image.
    """

    bottom = 0

    for seg in Segments():

        if SegEnd(seg) > bottom:
            bottom = SegEnd(seg)

    return bottom

def upd_reg_comm(src, dst):
    """
    Given an address, retrieve any existing regular comments and append 
    comment data for the newly created comment, as this won't be auto-
    generated on the caller side.
    """

    new_comm = "CODE XREF 0x%08x" % dst
    old_comm = GetCommentEx(src, 0)

    if old_comm:
        comm = "%s\n%s" % (old_comm, new_comm)
    else:
        comm = new_comm

    MakeComm(src, comm)

def call_xref_add(src, dst):
    """
    Add a xref for a given source and destination and update the regular
    comment at the caller address to represent the change.
    """

    add_cref(src, dst, fl_CF)
    upd_reg_comm(src,dst)

def parse_lines(call_list):
    """
    Parse through the input provided by the corresponding pin tool and
    add new xrefs for idenitfied virtual calls.
    """

    bad_lines = []
    existing_xref = []
    out_of_range = []
    new_xref = []
    range_bottom = image_range()

    for line in call_list:
        # strip off newlines for accurate length checking
        line = line.rstrip()

        if len(line) < 17:
            print "ERROR: String too short:\n\t%s" % line
            bad_lines.append(line)

        elif len(line) > 17:
            print "ERROR: String too long:\n\t%s%d" % (line,len(line))
            bad_lines.append(line)

        else:
            src, dst = line.split(":")
            src = int(src, 16)
            dst = int(dst, 16)

            if src < 0 or src > range_bottom:	
                #print "DEBUG: src call is out of range"
                out_of_range.append(line)

            elif dst < 0 or dst > range_bottom:	
                #print "DEBUG: call dst is out of range"
                out_of_range.append(line)

            elif src == BADADDR:
                print "DEBUG: bad src address: %x" % src
                bad_lines.append(line)

            elif dst == BADADDR:
                print "DEBUG: bad dst address: %x" % dst
                bad_lines.append(line)
            
            elif dst in CodeRefsFrom( src, 0 ):
                #print "DEBUG: xref from %08x to %08x exists. Cool." % (src,dst)
                existing_xref.append(line)

            else:
                print "DEBUG: adding xref from %08x to %08x" % (src,dst)
                new_xref.append(line)
                call_xref_add(src,dst)
                # note - we could do some basic code coverage marking here as well

    return bad_lines, existing_xref, out_of_range, new_xref



input_file = AskFile(0, "*.out", "Select icalltrace input log")
f = open(input_file, 'rb')
result = parse_lines(f)
f.close


print "Bad lines: %d" % len(result[0])
print "Pre-existing cross-references: %d" % len(result[1])
print "Out-of-range callers: %d" % len(result[2])
print "New cross-references added: %d" % len(result[3])