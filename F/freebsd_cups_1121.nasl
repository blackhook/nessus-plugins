#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
# 
# This script has been deprecated by freebsd_pkg_05dcf751073311d9b45d000c41e2cdad.nasl.
#
# Disabled on 2011/10/01.

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
 script_id(14763);
 script_version("1.11");
 script_cve_id("CVE-2004-0558");

 script_name(english:"FreeBSD : cups -- print queue browser denial-of-service (27)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: cups-base');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.mysql.com/bug.php?id=3270
http://www.cups.org/str.php?L863
http://www.mantisbt.org/bugs/view.php?id=9533
http://www.phpbb.com/support/documents.php?mode=changelog');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/05dcf751-0733-11d9-b45d-000c41e2cdad.html');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/16");
 script_end_attributes();
 script_summary(english:"Check for cups-base");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

exit(0, "This plugin has been deprecated. Refer to plugin #37713 (freebsd_pkg_05dcf751073311d9b45d000c41e2cdad.nasl) instead.");

global_var cvss_score;
cvss_score=5;
include('freebsd_package.inc');


pkg_test(pkg:"cups-base<1.1.21");
