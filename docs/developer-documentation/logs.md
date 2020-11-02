# SSA Daemon Logs

The SSA Daemon uses the linux standard, `syslog`, to log information regarding its operation and errors that arise. Syslog records logs to files found in `/var/log`; there are several ways to access these files.

## Accessing/Reading Logs

To read syslog logs printed within `/var/log`, one of the following commands can be used:

`less /var/log/syslog` - Allows for scrolling through the entire log file from the terminal.

`tail /var/log/syslog` - Prints out the last ~20 log messages to the terminal.

To search for logs pertaining only to the ssa daemon, one can use `grep` to retrieve SSA-specific logs. Each log will be tagged with 'ssad' at the start of it; so, for example, if one wanted to see all logs coming from the SSA Daemon they could use `cat /var/log/syslog | grep ssad`.

