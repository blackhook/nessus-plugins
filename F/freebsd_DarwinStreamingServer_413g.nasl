#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_c7cad0f0671a11d8bdeb000a95bc6fae.nasl.
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
 script_id(12522);
 script_version("1.10");
 script_cve_id("CVE-2004-0169");

 script_name(english:"FreeBSD : Darwin Streaming Server denial-of-service vulnerability (1)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: DarwinStreamingServer');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://mozillanews.org/?article_date=2004-12-08+06-48-46
http://secunia.com/advisories/13129/
http://secunia.com/advisories/13254/
http://secunia.com/multiple_browsers_window_injection_vulnerability_test/
http://www.idefense.com/application/poi/display?id=75
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.mozilla.org/security/announce/2006/mfsa2006-16.html
http://www.mozilla.org/security/announce/2006/mfsa2006-17.html
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-6
http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
http://www.xfocus.org/advisories/200603/11.html
https://bugzilla.mozilla.org/show_bug.cgi?id=103638
https://bugzilla.mozilla.org/show_bug.cgi?id=273699');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/c7cad0f0-671a-11d8-bdeb-000a95bc6fae.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_end_attributes();
 script_summary(english:"Check for DarwinStreamingServer");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36968 (freebsd_pkg_c7cad0f0671a11d8bdeb000a95bc6fae.nasl) instead.");

global_var cvss_score;
cvss_score=5;
include('freebsd_package.inc');


pkg_test(pkg:"DarwinStreamingServer<=4.1.3g");
