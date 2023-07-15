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
  script_id(69096);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"FreeBSD : phpMyAdmin -- multiple vulnerabilities (f4a0212f-f797-11e2-9bb9-6805ca0b3d42)");
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
"The phpMyAdmin development team reports :

XSS due to unescaped HTML Output when executing a SQL query.

5 XSS vulnerabilities in setup, chart display, process list, and logo
link.

If a crafted version.json would be presented, an XSS could be
introduced.

Full path disclosure vulnerabilities.

XSS vulnerability when a text to link transformation is used.

Self-XSS due to unescaped HTML output in schema export.

SQL injection vulnerabilities, producing a privilege escalation
(control user)."
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-8.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-8/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-9.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-9/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-11.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-11/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-12.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-12/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-13.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-13/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-14.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-14/"
  );
  # http://www.phpmyadmin.net/home_page/security/PMASA-2013-15.php
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2013-15/"
  );
  # http://sourceforge.net/projects/phpmyadmin/files/phpMyAdmin/3.5.8.2/phpMyAdmin-3.5.8.2-notes.html/view
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c62957f"
  );
  # http://sourceforge.net/projects/phpmyadmin/files/phpMyAdmin/4.0.4.2/phpMyAdmin-4.0.4.2-notes.html/view
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a9f9ce4"
  );
  # https://vuxml.freebsd.org/freebsd/f4a0212f-f797-11e2-9bb9-6805ca0b3d42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?083b881d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin35");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin>=4.0<4.0.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin35>=3.5<3.5.8.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
