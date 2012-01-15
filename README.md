This is a port of the "Allegro Nameserver" to usocket,
bordeaux-threads and cl-ppcre, making it possible to run on Lisps
other than Allegro Common Lisp, which is the implementation it was
originally written for.

The port is not yet functional!

Here is the original readme.txt, edited to MD format:

# Allegro Nameserver #

## Features ##

Written in Common Lisp.  This means no exploitable buffer overruns.
Source code is freely available and is relatively small (compare to
 4 megabyte BIND9 distribution).
Can be a primary or secondary nameserver.
Can be used as just a caching nameserver.
Supports the DNS NOTIFY protocol (when used as a secondary)

## Setting up and using Allegro Nameserver ##

copy config.lisp.sample to config.lisp.

Edit config.lisp to your liking.  Notes on each of the parameters
follows:

```*dnsport*```: This is the port that the nameserver will listen on
and make queries from.  Most people will never need to change this.

```*dnshost*```: This is either nil or a string with the IP address of
the interface on which the program should listen for packets.  If
'nil', the program will listen on all available interfaces.

```*rootcache*```: The filename of the named.root file.  This file
contains bootstrapping information for the nameserver cache.

```*zonelist*```: This is the list of zones for which this nameserver
is the primary.  Each entry in the list is a list of (domain
zonefile), where 'domain' is a string that specifies the domain in
question and 'zonefile' specifies the filename which contains the zone
information.  Zone files are in the standard format (i.e., the same
format that BIND uses).

```*secondarylist*```: This is the list of zones for which this
nameserver is a secondary.  Each entry in the list is a list of
(domain zonefile masters).  'domain' is a string that specifies the
domain in question.  'zonefile' specifies the filename which will
store the zone information (the file is updated each time there is a
zone transfer from the primary nameserver).  'masters' is a list of IP
addresses (strings) of upstream nameservers for this zone.

save config.lisp

start Lisp

```(asdf:oos 'asdf:load-op :ans) ;; you may have to adjust your asdf:*central-registry*```

Evaluate ```(main)```.  

The nameserver is now running.  Try some test queries to make sure
it's working as you expect (useful tools for testing: dig, host, or
nslookup).
