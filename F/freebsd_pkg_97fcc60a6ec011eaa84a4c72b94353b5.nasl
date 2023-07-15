#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(134923);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/07");

  script_name(english:"FreeBSD : phpMyAdmin -- SQL injection (97fcc60a-6ec0-11ea-a84a-4c72b94353b5)");
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
"phpMyAdmin Team reports :

PMASA-2020-2 SQL injection vulnerability in the user accounts page,
particularly when changing a password

PMASA-2020-3 SQL injection vulnerability relating to the search
feature

PMASA-2020-4 SQL injection and XSS having to do with displaying
results

Removing of the 'options' field for the external transformation"
  );
  # https://www.phpmyadmin.net/news/2020/3/21/phpmyadmin-495-and-502-are-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c125faf3"
  );
  # https://vuxml.freebsd.org/freebsd/97fcc60a-6ec0-11ea-a84a-4c72b94353b5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aede1c5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin-php74");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin5-php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin5-php73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpMyAdmin5-php74");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php72<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php72>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php73<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php73>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php74<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin-php74>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5-php72<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5-php72>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5-php73<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5-php73>=5.0<5.0.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5-php74<4.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phpMyAdmin5-php74>=5.0<5.0.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
