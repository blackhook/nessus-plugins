#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_8471bb856fb011d8873f0020ed76ef5a.nasl.
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
 script_id(12523);
 script_version("1.12");
 script_bugtraq_id(9772);
 script_cve_id("CVE-2004-0354");
 script_cve_id("CVE-2004-0353");

 script_name(english:"FreeBSD : GNU Anubis buffer overflows and format string vulnerabilities (6)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: anubis');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.mozilla.org/security/announce/2006/mfsa2006-16.html
http://www.mozilla.org/security/announce/2006/mfsa2006-17.html
http://www.mozilla.org/security/announce/2006/mfsa2006-18.html
http://www.mozilla.org/security/announce/2006/mfsa2006-19.html
http://www.mozilla.org/security/announce/2006/mfsa2006-20.html
http://www.mozilla.org/security/announce/2006/mfsa2006-22.html
http://www.mozilla.org/security/announce/2006/mfsa2006-23.html
http://www.mozilla.org/security/announce/2006/mfsa2006-25.html
http://www.mozilla.org/security/announce/2006/mfsa2006-26.html
http://www.mozilla.org/security/announce/2006/mfsa2006-28.html
http://www.mozilla.org/security/announce/2006/mfsa2006-29.html
http://www.zerodayinitiative.com/advisories/ZDI-06-010.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/8471bb85-6fb0-11d8-873f-0020ed76ef5a.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_cvs_date("Date: 2018/07/20  0:18:52");
 script_end_attributes();
 script_summary(english:"Check for anubis");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #37292 (freebsd_pkg_8471bb856fb011d8873f0020ed76ef5a.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"anubis<=3.6.2_1");
