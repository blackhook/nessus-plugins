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
  script_id(124046);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/15  9:39:30");

  script_name(english:"FreeBSD : MySQL -- multiple vulnerabilities (4e1997e8-5de0-11e9-b95c-b499baebfeaf)");
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
"Oracle reports :

Critical Patch Update Oracle MySQL Executive Summary

This Critical Patch Update contains 44 new security fixes for Oracle
MySQL. 3 of these vulnerabilities may be remotely exploitable without
authentication, i.e., may be exploited over a network without
requiring user credentials.

The Oracle MySQL products and versions affected by vulnerabilities
that are fixed in this Critical Patch Update are: MySQL Server,
versions 5.6.43 and prior, 5.7.25 and prior, 8.0.15 and prior

Further details will be published by Oracle on 2019-04-16"
  );
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9166970d"
  );
  # https://vuxml.freebsd.org/freebsd/4e1997e8-5de0-11e9-b95c-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93634c43"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql80-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona57-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.64")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.39")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-server<10.2.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb103-server<10.3.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.44")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql80-server<8.0.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.64")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.44")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona57-server<5.7.26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
