# SSA DAemon Documentation







## About The Man Pages

The man pages are meant to provide clear instruction on the API of the SSA 
daemon in a simple, familiar format. The information provided within them 
overlaps quite a bit with the information found in the tutorials, but in 
general the manpages provide a more formal documentation of expected behavior 
from the daemon while the tutorials dive more into use cases through example 
code.

The man pages found in `man2` are not meant as a replacement of the POSIX 
socket man pages. Rather, they supplement the POSIX socket API with relevant 
information on functionality, best practice, and error codes specific to the 
Secure Socket API. All behavior defined in POSIX socket man pages are still 
applicable to sockets made using the SSA; however, unspecified behavior or 
function calls leading to undefined behavior will be treated in a way that 
will maintain the security and integrity of all connections held by the SSA 
Daemon. Such edge cases will be outlined in these man pages as well.

The specification of certain behaviors and return codes is as of yet a work in 
progress. For the time being, error codes are subject to change and behavior
additional to the POSIX socket specification is experimental for the time being.

Man pages are written in both Markdown (.md) and troff (no file extension). 
The Markdown files are converted into troff using Pandoc; a tutorial for how 
to correctly format the Markdown files in order to facilitate this can be found 
[here](https://eddieantonio.ca/blog/2015/12/18/authoring-manpages-in-markdown-with-pandoc/).
