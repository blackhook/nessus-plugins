#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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
  script_id(132410);
  script_version("1.1");
  script_cvs_date("Date: 2019/12/27");

  script_name(english:"FreeBSD : typo3 -- multiple vulnerabilities (1c9178aa-2709-11ea-9673-4c72b94353b5)");
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

It has been discovered that the output of field validation errors in
the Form Framework is vulnerable to cross-site scripting.

It has been discovered that t3:// URL handling and typolink
functionality are vulnerable to cross-site scripting. Not only regular
backend forms are affected but also frontend extensions which use the
rendering with typolink.

It has been discovered that the output table listing in the Files
backend module is vulnerable to cross-site scripting when a file
extension contains malicious sequences. Access to the file system of
the server - either directly or through synchronization - is required
to exploit the vulnerability.

It has been discovered that the extraction of manually uploaded ZIP
archives in Extension Manager is vulnerable to directory traversal.
Admin privileges are required in order to exploit this vulnerability.
Since TYPO3 v9 LTS, System Maintainer privileges are required as well.

Failing to properly escape user submitted content, class
QueryGenerator is vulnerable to SQL injection. Having system extension
ext:lowlevel installed and a valid backend user having administrator
privileges are required to exploit this vulnerability.

It has been discovered that classes QueryGenerator and QueryView are
vulnerable to insecure deserialization. Requirements for successfully
exploiting this vulnerability (one of the following) : - having system
extension ext:lowlevel (Backend Module: DB Check) installed and valid
backend user having administrator privileges - having system extension
ext:sys_action installed and valid backend user having limited
privileges

TYPO3 allows to upload files either in the backend user interface as
well as in custom developed extensions. To reduce the possibility to
upload potential malicious code TYPO3 uses the fileDenyPattern to deny
e.g. user submitted PHP scripts from being persisted. Besides that it
is possible for any editor to upload file assets using the file module
(fileadmin) or changing their avatar image shown in the TYPO3 backend.

Per default TYPO3 allows to upload and store HTML and SVG files as
well using the mentioned functionalities. Custom extension
implementations probably would also accept those files when only the
fileDenyPattern is evaluated.

Since HTML and SVG files - which might contain executable JavaScript
code per W3C standard - could be directly displayed in web clients,
the whole web application is exposed to be vulnerable concerning
Cross-Site Scripting. Currently the following scenarios are known -
given an authenticated regular editor is able to upload files using
the TYPO3 backend : - directly target a potential victim to a known
public resource in a URL, e.g. /fileadmin/malicious.svg or
/fileadmin/malicious.html - using the TypoScript content object
'SVG' (implemented in class ScalableVectorGraphicsContentObject)
having renderMode set to inline for SVG files (available since TYPO3
v9.0) - custom implementations that directly output and render markup
of HTML and SVG files

SVG files that are embedded using an img src='malicious.svg' tag
are not vulnerable since potential scripts are not executed in these
scenarios (see https://www.w3.org/wiki/SVG_Security). The icon API of
TYPO3 is not scope of this announcement since SVG icons need to be
registered using an individual implementation, which is not considered
as user submitted content.

It has been discovered that request handling in Extbase can be
vulnerable to insecure deserialization. User submitted payload has to
be signed with a corresponding HMAC-SHA1 using the sensitive TYPO3
encryptionKey as secret - invalid or unsigned payload is not
deserialized.

However, since sensitive information could have been leaked by
accident (e.g. in repositories or in commonly known and unprotected
backup files), there is the possibility that attackers know the
private encryptionKey and are able to calculate the required HMAC-SHA1
to allow a malicious payload to be deserialized.

Requirements for successfully exploiting this vulnerability (all of
the following) : - rendering at least one Extbase plugin in the
frontend - encryptionKey has been leaked (from LocalConfiguration.php
or corresponding .env file)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2019-021/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2019-022/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2019-023/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2019-024/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2019-025/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2019-026/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-psa-2019-010/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-psa-2019-011/"
  );
  # https://vuxml.freebsd.org/freebsd/1c9178aa-2709-11ea-9673-4c72b94353b5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dffc731"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"typo3-8<8.7.30")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3-9<9.5.13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
