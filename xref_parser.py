# xref_parser.py
#
# An IDAPython script for parsing call data generated using a 
# corresponding pin tool (xref_finder.dll)
# 
# Author: bNull

from idaapi import *
import re

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

def print_stats(formatted_stats):
    """
    Return a log statement to display some basic statistics about what 
    was in the log.
    """
    print "Bad lines: %d" % formatted_stats['bad']
    print "Pre-existing cross-references: %d" % formatted_stats['existing']
    print "Out-of-range addresses: %d" % formatted_stats['oor']
    print "New cross-references added: %d" % formatted_stats['new_xrefs']
    print "Reference - previous function count: %d" % formatted_stats['old_funcs']

def fun_count(max_range):
    """
    A simple function the total number of functions that IDA recognizes.
    """
    return sum( 1 for i in Functions(0, max_range))

def add_len_stat(stat_dict, name, stat):
    stat_dict[name] = len(stat)
    return stat_dict

def parse_lines(call_list):
    """
    Parse through the input provided by the corresponding pin tool and
    add new xrefs for idenitfied virtual calls

    Returns an array of arrays of the raw log entries that matched paricular
    state. These states include:
        bad addresses
        pre-existing cross-references
        out-of-range addresses
        added cross-references
    """

    bad_lines = []
    existing_xref = []
    out_of_range = []
    new_xref = []
    range_bottom = image_range()
    stats = {'old_funcs' : fun_count(range_bottom)}

    for line in call_list:
        # strip off newlines for accurate length checking
        line = line.rstrip()

        if re.search(r"^#.*", line):
            # continue on comments
            continue
        elif len(line) < 17:
            print "ERROR: String too short:\n\t%s" % line
            bad_lines.append(line)

        elif len(line) > 17:
            print "ERROR: String too long:\n\t%s%d" % (line,len(line))
            bad_lines.append(line)

        else:
            src, dst = line.split(":")
            src = int(src, 16)
            dst = int(dst, 16)

            if (src == BADADDR) or (dst == BADADDR):
                # BADADDR are bad, mmmmkay?
                print "DEBUG: bad source or destination address: %x:%x" % (src,dst)
                bad_lines.append(line)

            elif src < 0 or src > range_bottom:
                # We can't build a xref for a call not made in the address
                # range of our binary.
                out_of_range.append(line)

            elif dst < 0 or dst > range_bottom:	
                # Likewise, We can't build a xref to a function that doesn't 
                # exist in the address range of our binary.
                out_of_range.append(line)

            elif dst in CodeRefsFrom( src, 0 ):
                # If the xref already exists, our job here is done
                existing_xref.append(line)

            else:
                # What we came for
                print "adding xref from 0x%08x to 0x%08x" % (src,dst)
                new_xref.append(line)
                call_xref_add(src,dst)
                # note - we could do some basic code coverage marking here as well
    
    # NOTE - we don't provide stats about the number of new functions auto-discovered,
    # because it seems that IDA won't recognize them until the script compeltes. We do
    # provide the old number of functions so that the user can manually spot check for
    # themselves.
    stats = add_len_stat(stats, "bad", bad_lines)
    stats = add_len_stat(stats, "existing", existing_xref)
    stats = add_len_stat(stats, "oor", out_of_range)
    stats = add_len_stat(stats, "new_xrefs", new_xref)

    return stats



input_file = AskFile(0, "*.out", "Select icalltrace input log")
f = open(input_file, 'rb')

print_stats(parse_lines(f))

f.close


