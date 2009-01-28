Yet Another Brute Force Detector is a program that blocks brute forcers.
It does so by scanning logfiles for patterns of failed logins and
similar and creates a blacklist of all hosts that have too much hits.
The user is responsible for using this list to block further login
attempts (to whatever service they seem fit) by these IP addresses.

To install YABFD, checkout the source with subversion (`svn co
https://0brg.net/svn/yabfd/trunk/`), create a configuration file and run
the `yabfd` script whenever you want to scan logfiles and update your
blacklist. This can be done by putting yabfd in your crontab, for
example:

* * * * * /usr/local/yabfd/yabfd

If something is unclear or something goes wrong, do not hesitate to
contact me.

Thank you for using YABFD.

Hraban Luyat
hraban at 0brg dot net
