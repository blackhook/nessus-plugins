#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61557);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"FreeBSD : typo3 -- Multiple vulernabilities in TYPO3 Core (48bcb4b2-e708-11e1-a59d-000d601460a4)");
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
"Typo Security Team reports :

It has been discovered that TYPO3 Core is vulnerable to Cross-Site
Scripting, Information Disclosure, Insecure Unserialize leading to
Arbitrary Code Execution.

TYPO3 Backend Help System - Due to a missing signature (HMAC) for a
parameter in the view_help.php file, an attacker could unserialize
arbitrary objects within TYPO3. We are aware of a working exploit,
which can lead to arbitrary code execution. A valid backend user login
or multiple successful cross site request forgery attacks are required
to exploit this vulnerability.

TYPO3 Backend - Failing to properly HTML-encode user input in several
places, the TYPO3 backend is susceptible to Cross-Site Scripting. A
valid backend user is required to exploit these vulnerabilities.

TYPO3 Backend - Accessing the configuration module discloses the
Encryption Key. A valid backend user with access to the configuration
module is required to exploit this vulnerability.

TYPO3 HTML Sanitizing API - By not removing several HTML5 JavaScript
events, the API method t3lib_div::RemoveXSS() fails to filter
specially crafted HTML injections, thus is susceptible to Cross-Site
Scripting. Failing to properly encode for JavaScript the API method
t3lib_div::quoteJSvalue(), it is susceptible to Cross-Site Scripting.

TYPO3 Install Tool - Failing to properly sanitize user input, the
Install Tool is susceptible to Cross-Site Scripting."
  );
  # https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2012-004/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef693360"
  );
  # https://vuxml.freebsd.org/freebsd/48bcb4b2-e708-11e1-a59d-000d601460a4.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7596f565"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"typo3>=4.5.0<4.5.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3>=4.6.0<4.6.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3>=4.7.0<4.7.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
