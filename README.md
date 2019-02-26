# frac_rift
FRAC and RIFT

Retrieve Interesting Files Tool (RIFT)
Retrieve Interesting Files Tool (RIFT) was written to obtain a set of files/directories in an automated forensically sound manner. RIFT retrieves files/directories based upon a regex list of filenames/directories. The tool starts off by parsing the output from the Sleuthkit’s FLS command of the $MFT. Each line of output is compared to the regex list to check for a match. If there is a match, Sleuthkit’s ICAT is used to forensically retrieve the file and save it to the location specified.

Forensic Response ACquisition (FRAC)
Forensic Response ACquistion (FRAC) is a network tool that uses RIFT to retrieve forensically interesting files. Its primary goal is to pull back files for review during incident response. The tool will take an IP range and connect to each machine to run a command. If it cannot connect to an IP address it will log the IP as unresponsive so that it can be re-ran at a later time. FRAC uses either PAExec or Winexe to connect to the remote Windows boxes. Once connected, it will run the command given to it on the machine and then disconnect. Primarily, FRAC is used to retrieve files like Atjobs or system hives, however, it is possible to retrieve the system memory using Winpmem. The section entitled “Running Other Commands with FRAC” has details on how to run other commands with FRAC.

Please see the PDF for how to use.
