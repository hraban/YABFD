==Introduction==

  Yet Another Brute Force Detector is a program that blocks brute
  forcers.  It does so by scanning logfiles for patterns of failed
  logins and similar and creates a blacklist of all hosts that have too
  much hits.  The user is responsible for using this list to block
  further login attempts (to whatever service they see fit) by these IP
  addresses.

==Installation==

  To install YABFD, checkout the source with subversion (`svn co
  https://0brg.net/svn/yabfd/trunk/`), create a configuration file and
  run the `yabfd` script whenever you want to scan logfiles and update
  your blacklist. This can be done by putting yabfd in your crontab, for
  example:

  * * * * * /usr/local/yabfd/yabfd

  There are various ways to detect whether or not the blacklist was
  modified. One way is to create an md5sum or crc of the file before you
  run YABFD, and compare it to the same hash afterwards. For example, to
  restart Squid based on updates to the banlist (all on one line):

  * * * * * crc=`cksum /etc/hosts.deny.yabfd` ; /usr/local/yabfd/yabfd ; sort -o /etc/hosts.deny.yabfd /etc/hosts.deny.yabfd ; if [ "$crc" != "$(cksum /etc/hosts.deny.yabfd)" ] ; then /etc/init.d/squid reload ; fi

  The sorting is necessary because YABFD's output is not sorted.
  Therefore the same blacklist can have different hashes across
  different runs.

==Usage==

  All the configuration options are explained in the yabfd.conf.example
  file. The usage options are explained in the help message yielded by
  running yabfd with the --help option.

==Banning==

  YABFD's output can be stored by using "printers". The example
  configuration file details which printers exist and how to use them.
  You can combine several printers, or use none at all, if you wish.

  For example, YABFD can output blacklists as a newline seperated list
  of IP addresses. Some programs can deal with this, some can not. The
  TCP wrapper service, for example, can. You can use the list by putting
  this in your /etc/hosts.deny:

  ALL : /etc/hosts.deny.yabfd : DENY

==Security==

  How secure this program can make your system depends on the program
  itself, obviously, but also on how you use it.  Check the regular
  expressions and the other options that you use and make sure that your
  services are aware of the latest updates to the blacklist. The example
  above using the CRC could be fooled if somebody controlled enough
  hosts to manipulate the list in such a way that the new host will not
  cause a different CRC. To avoid this you can use other hashes in
  addition, such as MD5 or SHA1 or you can just compare the entire
  contents of the file (the only way to ever be really sure). It all
  depends on your needs.

  YABFD itself is still in an early development stage. Commits to the
  svn trunk/ are not tested thoroughly and the overall integrity of the
  system has never been checked either. The code was written in a
  "fail-fast", "pessimistic" style. If an error occurs that could only
  cause false positives (more bans than necessary), it is only logged.
  If an error could cause false negatives, the program crashes a.s.a.p.

== Bugs ==

  Don't forget to check BUGS.txt for the bugs that you should know
  about.

If something is unclear or if something goes wrong, do not hesitate to
contact me.

Thank you for using YABFD.

Hraban Luyat
hraban at 0brg dot net
