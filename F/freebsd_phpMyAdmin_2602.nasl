#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated by freebsd_pkg_fc07c9ca22ce11d9814e0001020eed82.nasl.
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
 script_id(15574);
 script_version("1.22");
 script_bugtraq_id(11391);

 script_name(english:"FreeBSD : phpmyadmin -- remote command execution vulnerability (143)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: phpMyAdmin');
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://drupal.org/files/sa-2005-007/advisory.txt
http://scary.beasts.org/security/CESA-2004-001.txt
http://sourceforge.net/project/shownotes.php?release_id=274709
http://sourceforge.net/tracker/index.php?func=detail&amp;aid=1044864&amp;group_id=23067&amp;atid=377408
http://www.lighttpd.net/security/lighttpd_sa_2008_05.txt
http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey1.0.3
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-44.html
http://www.mozilla.org/security/announce/2008/mfsa2008-47.html
http://www.mozilla.org/security/announce/2008/mfsa2008-48.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/fc07c9ca-22ce-11d9-814e-0001020eed82.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/27");
 script_cvs_date("Date: 2018/08/22 16:49:14");
 script_end_attributes();
 script_cve_id("CVE-2004-2630");
 script_summary(english:"Check for phpMyAdmin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #36697 (freebsd_pkg_fc07c9ca22ce11d9814e0001020eed82.nasl) instead.");

global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


pkg_test(pkg:"phpMyAdmin<2.6.0.2");

pkg_test(pkg:"phpmyadmin<2.6.0.2");
