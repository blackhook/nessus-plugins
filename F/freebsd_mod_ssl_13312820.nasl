#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_4238151d207a11d9bfe20090962cff2a.nasl.
#
# Disabled on 2011/10/02.
#

#
# (C) Tenable Network Security, Inc.
#
# This script contains information extracted from VuXML :
#
# Copyright 2003-2006 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#   copyright notice, this list of conditions and the following
#   disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#   published online in any format, converted to PDF, PostScript,
#   RTF and other formats) must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#

include('compat.inc');

if ( description )
{
 script_id(15576);
 script_version("1.9");
 script_cve_id("CVE-2004-0885");

 script_name(english:"FreeBSD : mod_ssl -- SSLCipherSuite bypass (112)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: apache+mod_ssl+ipv6');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=120508
http://forums.cacti.net/about18846-0-asc-0.html
http://issues.apache.org/bugzilla/show_bug.cgi?id=31505
http://projects.edgewall.com/trac/wiki/ChangeLog
http://www.mozilla.org/security/announce/2008/mfsa2008-60.html
http://www.mozilla.org/security/announce/2008/mfsa2008-61.html
http://www.mozilla.org/security/announce/2008/mfsa2008-62.html
http://www.mozilla.org/security/announce/2008/mfsa2008-63.html
http://www.mozilla.org/security/announce/2008/mfsa2008-64.html
http://www.samba.org/samba/whatsnew/samba-3.0.5.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/4238151d-207a-11d9-bfe2-0090962cff2a.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/27");
 script_end_attributes();
 script_summary(english:"Check for apache+mod_ssl+ipv6");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #37846 (freebsd_pkg_4238151d207a11d9bfe20090962cff2a.nasl) instead.");

global_var cvss_score;
cvss_score=7;
include('freebsd_package.inc');


pkg_test(pkg:"ru-apache+mod_ssl<=1.3.31+30.20+2.8.18");

pkg_test(pkg:"apache+mod_ssl<1.3.31+2.8.20");

pkg_test(pkg:"apache+mod_ssl+ipv6<=1.3.31+2.8.18_4");

pkg_test(pkg:"apache2<=2.0.52_1");
