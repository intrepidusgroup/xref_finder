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
and adds the cross-references accordingly. To highlight what new cross-
references have been built, the script will add regular comments next to
each "call" instruction.

This tool is intended to solve a very specific purpose, but Pin and 
IDAPython could be further utilized to do a lot more interesting things.

Pre-requisites
===========
These tools are designed for use with IDA Pro. You'll also need IDAPython
and Pin.

Building the Pin tool
===========
Note: This Pin tool has only been tested on Windows, using Visual Studio 
2010. 

Move the xref_finder directory into the source/tools/ directory within your
Pin directory. From a Visual Studio command prompt, change into the 
xref_finder directory and simply type "nmake". By default, the resulting
tool can be found within a new "obj-ia32" directory (on x86 architecture).

Running the Pin tool
===========
Pin tools are essentially libraries, intended to be used with the Pin 
application. From your Pin directory, run something like the following.

pin -t path\to\xref_finder.dll -- calc.exe

In this example, "calc.exe" will launch and a file called "xrefs_omg.out" 
will be created in the directory from which Pin was run.

The tool doesn't account for child processes (yet?) so mileage may vary.

Running the IDAPython script
===========
I suspect that this is self-explanatory. Suck in the output the xref_finder
output (by default, "xref_omg.out").

Quirks
===========
There may be some. They may be more obvious to you than to me. Because I 
wrote this tool to actually use, I am interested in improving its 
functionality and reliability. There's a very good chance that you are a
better Python and/or C++ programmer with a better understanding of how
software works. Please be sure to share any suggestions, comments, or
criticisms.

bNull
bnull@offenseindepth.com