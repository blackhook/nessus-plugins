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
  script_id(103475);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14508", "CVE-2017-14509", "CVE-2017-14510");

  script_name(english:"FreeBSD : sugarcrm -- multiple vulnerabilities (3b776502-f601-44e0-87cd-b63f1b9ae42a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"sugarcrm developers report :

An issue was discovered in SugarCRM before 7.7.2.3, 7.8.x before
7.8.2.2, and 7.9.x before 7.9.2.0 (and Sugar Community Edition
6.5.26). Several areas have been identified in the Documents and
Emails module that could allow an authenticated user to perform SQL
injection, as demonstrated by a backslash character at the end of a
bean_id to modules/Emails/DetailView.php. An attacker could exploit
these vulnerabilities by sending a crafted SQL request to the affected
areas. An exploit could allow the attacker to modify the SQL database.
Proper SQL escaping has been added to prevent such exploits.

An issue was discovered in SugarCRM before 7.7.2.3, 7.8.x before
7.8.2.2, and 7.9.x before 7.9.2.0 (and Sugar Community Edition
6.5.26). A remote file inclusion has been identified in the Connectors
module allowing authenticated users to include remotely accessible
system files via a query string. Proper input validation has been
added to mitigate this issue.

An issue was discovered in SugarCRM before 7.7.2.3, 7.8.x before
7.8.2.2, and 7.9.x before 7.9.2.0 (and Sugar Community Edition
6.5.26). The WebToLeadCapture functionality is found vulnerable to
unauthenticated cross-site scripting (XSS) attacks. This attack vector
is mitigated by proper validating the redirect URL values being passed
along."
  );
  # https://blog.ripstech.com/2017/sugarcrm-security-diet-multiple-vulnerabilities/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6737bac2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-006/"
  );
  # https://blog.ripstech.com/2017/sugarcrm-security-diet-multiple-vulnerabilities/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6737bac2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-007/"
  );
  # https://blog.ripstech.com/2017/sugarcrm-security-diet-multiple-vulnerabilities/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6737bac2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-008/"
  );
  # https://vuxml.freebsd.org/freebsd/3b776502-f601-44e0-87cd-b63f1b9ae42a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cff4001"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sugarcrm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"sugarcrm<=6.5.26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
