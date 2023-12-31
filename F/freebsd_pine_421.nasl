#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_5789a92e5d7f11d880e30020ed76ef5a.nasl.
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
 script_id(12599);
 script_version("1.10");

 script_name(english:"FreeBSD : pine remotely exploitable buffer overflow in newmail.c (148)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: iw-pine');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://gallery.menalto.com/modules.php?op=modload&amp;name=News&amp;file=article&amp;sid=147
http://secunia.com/advisories/9096
http://www.freebsd.org/cgi/cvsweb.cgi/ports/mail/pine4/Makefile?rev=1.43&amp;content-type=text/x-cvsweb-markup
http://www.gnu.org/software/gnats/gnats.html
http://www.mozilla.org/security/announce/2008/mfsa2008-60.html
http://www.mozilla.org/security/announce/2008/mfsa2008-61.html
http://www.phpmyadmin.net/home_page/security/PMASA-2008-10.php
http://www.securiteam.com/unixfocus/5CP0N0UAAA.html
http://x82.inetcop.org/h0me/adv1sor1es/INCSA.2003-0x82-018-GNATS-bt.txt');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/5789a92e-5d7f-11d8-80e3-0020ed76ef5a.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_end_attributes();
 script_summary(english:"Check for iw-pine");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36654 (freebsd_pkg_5789a92e5d7f11d880e30020ed76ef5a.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"zh-pine<=4.21");

pkg_test(pkg:"iw-pine<=4.21");

pkg_test(pkg:"pine<=4.21");

pkg_test(pkg:"pine4-ssl<=4.21");
