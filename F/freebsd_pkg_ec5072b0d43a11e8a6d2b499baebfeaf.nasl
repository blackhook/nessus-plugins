#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2022 Jacques Vidrine and contributors
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
  script_id(118248);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/07");

  script_cve_id("CVE-2016-9843", "CVE-2018-3133", "CVE-2018-3137", "CVE-2018-3143", "CVE-2018-3144", "CVE-2018-3145", "CVE-2018-3155", "CVE-2018-3156", "CVE-2018-3161", "CVE-2018-3162", "CVE-2018-3170", "CVE-2018-3171", "CVE-2018-3173", "CVE-2018-3174", "CVE-2018-3182", "CVE-2018-3185", "CVE-2018-3186", "CVE-2018-3187", "CVE-2018-3195", "CVE-2018-3200", "CVE-2018-3203", "CVE-2018-3212", "CVE-2018-3247", "CVE-2018-3251", "CVE-2018-3277", "CVE-2018-3278", "CVE-2018-3279", "CVE-2018-3280", "CVE-2018-3282", "CVE-2018-3283", "CVE-2018-3284", "CVE-2018-3286");

  script_name(english:"FreeBSD : MySQL -- multiple vulnerabilities (ec5072b0-d43a-11e8-a6d2-b499baebfeaf)");
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

Please reference CVE/URL list for details"
  );
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixMSQL
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8db52af"
  );
  # https://vuxml.freebsd.org/freebsd/ec5072b0-d43a-11e8-a6d2-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fc9d49a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9843");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql80-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona57-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.62")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-server<10.0.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-server<10.2.19")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb103-server<10.3.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-server<5.5.62")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql80-server<8.0.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.62")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.42")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona57-server<5.7.24")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
