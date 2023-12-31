#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated as the VuXML entry has been
# superseded by VuXML entry 2dc764fa-40c0-11dc-aeac-02e0185f8d72.
#
# Disabled on 2011/10/02. Deprecated by
# freebsd_pkg_ff284bf03f3211dca79a0016179b2dd5.nasl.

#
# (C) Tenable Network Security
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

include("compat.inc");

if ( description )
{
 script_id(25814);
 script_version("1.11");
 script_bugtraq_id(24965);
 script_cve_id("CVE-2007-3798");

 script_name(english:"FreeBSD : tcpdump -- remote integer underflow vulnerability (983) (deprecated)");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing an update to the system

The following package is affected: tcpdump
This plugin is deprecated by plugin ID 25833,
freebsd_pkg_ff284bf03f3211dca79a0016179b2dd5.nasl");
 script_set_attribute(attribute:"solution", value:
"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/31");
 script_cvs_date("Date: 2018/07/20  0:18:52");
 script_end_attributes();

 script_summary(english:"Check for tcpdump");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

exit(0, "This plugin has been deprecated as the associated VuXML entry has\nbeen superseded by plugin ID 25833.");
