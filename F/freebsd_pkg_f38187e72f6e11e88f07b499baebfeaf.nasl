#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
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

include("compat.inc");

if (description)
{
  script_id(108626);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/10 11:49:47");

  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1302", "CVE-2018-1303", "CVE-2018-1312");

  script_name(english:"FreeBSD : apache -- multiple vulnerabilities (f38187e7-2f6e-11e8-8f07-b499baebfeaf)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache httpd reports :

Out of bound write in mod_authnz_ldap with AuthLDAPCharsetConfig
enabled (CVE-2017-15710)

mod_session: CGI-like applications that intend to read from
mod_session's 'SessionEnv ON' could be fooled into reading
user-supplied data instead. (CVE-2018-1283)

mod_cache_socache: Fix request headers parsing to avoid a possible
crash with specially crafted input data. (CVE-2018-1303)

core: Possible crash with excessively long HTTP request headers.
Impractical to exploit with a production build and production
LogLevel. (CVE-2018-1301)

core: Configure the regular expression engine to match '$' to the end
of the input string only, excluding matching the end of any embedded
newline characters. Behavior can be changed with new directive
'RegexDefaultOptions'. (CVE-2017-15715)

mod_auth_digest: Fix generation of nonce values to prevent replay
attacks across servers using a common Digest domain. This change may
cause problems if used with round robin load balancers.
(CVE-2018-1312)

mod_http2: Potential crash w/ mod_http2. (CVE-2018-1302)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.apache.org/dist/httpd/CHANGES_2.4.33"
  );
  # https://vuxml.freebsd.org/freebsd/f38187e7-2f6e-11e8-8f07-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d6e8b06"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"apache24<2.4.30")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22<2.2.34_5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
