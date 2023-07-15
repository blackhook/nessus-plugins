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
  script_id(111142);
  script_version("1.2");
  script_cvs_date("Date: 2018/11/10 11:49:47");

  script_name(english:"FreeBSD : typo3 -- multiple vulnerabilities (ef013039-89cd-11e8-84e9-00e04c1ea73d)");
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

It has been discovered that TYPO3's Salted Password system extension
(which is a mandatory system component) is vulnerable to
Authentication Bypass when using hashing methods which are related by
PHP class inheritance. In standard TYPO3 core distributions stored
passwords using the blowfish hashing algorithm can be overridden when
using MD5 as the default hashing algorithm by just knowing a valid
username. Per default the Portable PHP hashing algorithm (PHPass) is
used which is not vulnerable.

Phar files (formerly known as 'PHP archives') can act als self
extracting archives which leads to the fact that source code is
executed when Phar files are invoked. The Phar file format is not
limited to be stored with a dedicated file extension - 'bundle.phar'
would be valid as well as 'bundle.txt' would be. This way, Phar files
can be obfuscated as image or text file which would not be denied from
being uploaded and persisted to a TYPO3 installation. Due to a missing
sanitization of user input, those Phar files can be invoked by
manipulated URLs in TYPO3 backend forms. A valid backend user account
is needed to exploit this vulnerability. In theory the attack vector
would be possible in the TYPO3 frontend as well, however no functional
exploit has been identified so far.

Failing to properly dissociate system related configuration from user
generated configuration, the Form Framework (system extension 'form')
is vulnerable to SQL injection and Privilege Escalation. Basically
instructions can be persisted to a form definition file that were not
configured to be modified - this applies to definitions managed using
the form editor module as well as direct file upload using the regular
file list module. A valid backend user account as well as having
system extension form activated are needed in order to exploit this
vulnerability.

It has been discovered that the Form Framework (system extension
'form') is vulnerable to Insecure Deserialization when being used with
the additional PHP PECL package 'yaml', which is capable of
unserializing YAML contents to PHP objects. A valid backend user
account as well as having PHP setting 'yaml.decode_php' enabled is
needed to exploit this vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2018-001/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2018-002/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2018-003/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://typo3.org/security/advisory/typo3-core-sa-2018-004/"
  );
  # https://vuxml.freebsd.org/freebsd/ef013039-89cd-11e8-84e9-00e04c1ea73d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc40379c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/18");
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

if (pkg_test(save_report:TRUE, pkg:"typo3-7<7.6.30")) flag++;
if (pkg_test(save_report:TRUE, pkg:"typo3-8<8.7.17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
