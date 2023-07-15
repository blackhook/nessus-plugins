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
  script_id(119701);
  script_version("1.1");
  script_cvs_date("Date: 2018/12/17 10:33:00");

  script_name(english:"FreeBSD : typo3 -- multiple vulnerabilities (bab29816-ff93-11e8-b05b-00e04c1ea73d)");
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
"Typo3 core team reports :

CKEditor 4.11 fixes an XSS vulnerability in the HTML parser reported
by maxarr. The vulnerability stemmed from the fact that it was
possible to execute XSS inside the CKEditor source area after
persuading the victim to: (i) switch CKEditor to source mode, then
(ii) paste a specially crafted HTML code, prepared by the attacker,
into the opened CKEditor source area, and (iii) switch back to WYSIWYG
mode. Although this is an unlikely scenario, we recommend to upgrade
to the latest editor version.

Failing to properly encode user input, online media asset rendering
(*.youtube and *.vimeo files) is vulnerable to cross-site scripting. A
valid backend user account or write access on the server system (e.g.
SFTP) is needed in order to exploit this vulnerability.

Failing to properly encode user input, notifications shown in modal
windows in the TYPO3 backend are vulnerable to cross-site scripting. A
valid backend user account is needed in order to exploit this
vulnerability.

Failing to properly encode user input, login status display is
vulnerable to cross-site scripting in the website frontend. A valid
user account is needed in order to exploit this vulnerability - either
a backend user or a frontend user having the possibility to modify
their user profile.

Template patterns that are affected are :

- ###FEUSER_[fieldName]### using system extension felogin

- <!--###USERNAME###--> for regular frontend rendering (pattern can be
defined individually using TypoScript setting
config.USERNAME_substToken)

It has been discovered that cookies created in the Install Tool are
not hardened to be submitted only via HTTP. In combination with other
vulnerabilities such as cross-site scripting it can lead to hijacking
an active and valid session in the Install Tool.

The Install Tool exposes the current TYPO3 version number to
non-authenticated users.

Online Media Asset Handling (*.youtube and *.vimeo files) in the TYPO3
backend is vulnerable to denial of service. Putting large files with
according file extensions results in high consumption of system
resources. This can lead to exceeding limits of the current PHP
process which results in a dysfunctional backend component. A valid
backend user account or write access on the server system (e.g. SFTP)
is needed in order to exploit this vulnerability.

TYPO3's built-in record registration functionality (aka 'basic
shopping cart') using recs URL parameters is vulnerable to denial of
service. Failing to properly ensure that anonymous user sessions are
valid, attackers can use this vulnerability in order to create an
arbitrary amount of individual session-data records in the database."
  );
  # https://typo3.org/article/typo3-952-8721-and-7632-security-releases-published/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b468d07a"
  );
  # https://vuxml.freebsd.org/freebsd/bab29816-ff93-11e8-b05b-00e04c1ea73d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?277a1048"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");
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

if (pkg_test(save_report:TRUE, pkg:"typo3-8<8.7.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3-9<9.5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
