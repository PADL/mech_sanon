SAnon
=====

This is a port of Heimdal's simple anonymous GSS-API mechanism to MIT. It will
not work with Heimdal; use a recent version Heimdal for that. It has been
tested against MIT Kerberos 1.15.5, 1.17.1 and master (as of April 2020), on
both macOS 10.14.6 and Linux (CentOS 6.10).

Note: it will not work with MIT Kerberos 1.10 as shipped with RHEL/CentOS 6.
These versions are too old to support the encryption algorithm used by SAnon.
1.15 is the earliest version that is supported.

To build and install:

% sh autogen.sh
% ./configure --prefix=/usr/local/mit --with-krb5=/usr/local/mit

(adjust prefixes to suit)

You will then need to (again, adjusting prefixes) copy the mech file to
/usr/local/mit/etc/gss/mech. You can test with the gss-sample application with
the following arguments:

% ./gss-server -port 5555 host@localhost
% ./gss-client -port 5555 -spnego -user WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS \
  localhost host@localhost Testing

Questions? Email me at lukeh@padl.com.
