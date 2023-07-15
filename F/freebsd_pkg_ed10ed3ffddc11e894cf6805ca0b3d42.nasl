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
  script_id(119637);
  script_version("1.1");
  script_cvs_date("Date: 2018/12/13 16:48:46");

  script_name(english:"FreeBSD : phpMyAdmin -- multiple vulnerabilities (ed10ed3f-fddc-11e8-94cf-6805ca0b3d42)");
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
"The phpMyAdmin development team reports : Summary Local file inclusion
through transformation feature Description A flaw has been found where
an attacker can exploit phpMyAdmin to leak the contents of a local
file. The attacker must have access to the phpMyAdmin Configuration
Storage tables, although these can easily be created in any database
to which the attacker has access. An attacker must have valid
credentials to log in to phpMyAdmin; this vulnerability does not allow
an attacker to circumvent the login system. Severity We consider this
vulnerability to be severe. Summary XSRF/CSRF vulnerability in
phpMyAdmin Description By deceiving a user to click on a crafted URL,
it is possible to perform harmful SQL operations such as renaming
databases, creating new tables/routines, deleting designer pages,
adding/deleting users, updating user passwords, killing SQL processes,
etc. Severity We consider this vulnerability to be of moderate
severity. Summary XSS vulnerability in navigation tree Description A
Cross-Site Scripting vulnerability was found in the navigation tree,
where an attacker can deliver a payload to a user through a
specially crafted database/table name. Severity We consider this
attack to be of moderate severity. Mitigation factor The stored XSS
vulnerabilities can be triggered only by someone who logged in to
phpMyAdmin, as the usual token protection prevents non-logged-in users
from accessing the required forms."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2018-6/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2018-7/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2018-8/"
  );
  # https://vuxml.freebsd.org/freebsd/ed10ed3f-fddc-11e8-94cf-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5a55a51"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php71");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php72");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");
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

if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin<4.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php56<4.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php70<4.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php71<4.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php72<4.8.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
