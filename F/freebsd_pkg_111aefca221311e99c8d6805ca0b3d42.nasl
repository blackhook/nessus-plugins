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
  script_id(121403);
  script_version("1.1");
  script_cvs_date("Date: 2019/01/28 10:02:20");

  script_name(english:"FreeBSD : phpMyAdmin -- File disclosure and SQL injection (111aefca-2213-11e9-9c8d-6805ca0b3d42)");
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
"The phpMyAdmin development team reports : Summary Arbitrary file read
vulnerability Description When AllowArbitraryServer configuration set
to true, with the use of a rogue MySQL server, an attacker can read
any file on the server that the web server's user can access.

phpMyadmin attempts to block the use of LOAD DATA INFILE, but due to a
bug in PHP, this check is not honored. Additionally, when using the
'mysql' extension, mysql.allow_local_infile is enabled by default.
Both of these conditions allow the attack to occur. Severity We
consider this vulnerability to be critical. Mitigation factor This
attack can be mitigated by setting the `AllowArbitraryServer`
configuration directive to false (which is the default value).
Affected Versions phpMyAdmin versions from at least 4.0 through 4.8.4
are affected Summary SQL injection in Designer feature Description A
vulnerability was reported where a specially crafted username can be
used to trigger a SQL injection attack through the designer feature.
Severity We consider this vulnerability to be serious. Affected
Versions phpMyAdmin versions from 4.5.0 through 4.8.4 are affected"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2019-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2019-2/"
  );
  # https://vuxml.freebsd.org/freebsd/111aefca-2213-11e9-9c8d-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0cca6f90"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/28");
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

if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin<4.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php56<4.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php70<4.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php71<4.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php72<4.8.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
