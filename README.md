xref_finder
===========
xref_finder is a pair of tools that can be used for adding cross-references
into an IDA Pro database that can't be identified using strictly static 
analysis, such as virtual calls (i.e. call eax). The idea was inspired by
Portnoy's writeup on scripting the creation of xrefs using IDAPython 
(http://dvlabs.tippingpoint.com/blog/2012/02/23/adding-xrefs-via-idapy).

The first, xref_finder, is a Pin tool, which must be compiled and executed
using Pin (http://www.pintool.org/). Running the desired executable with 
xref_finder will generate a log of caller to callee mappings.

The second, xref_parser, is an IDAPython plugin which parses this log, 
determines whether or not a particular mapping is eligible to be added as
a cross-reference (valid address range, is not an existing cross-reference)
and adds the cross-references accordingly.

This tool is intended to solve a very specific purpose, but Pin and 
IDAPython could be further utilized to do a lot more interesting things.
