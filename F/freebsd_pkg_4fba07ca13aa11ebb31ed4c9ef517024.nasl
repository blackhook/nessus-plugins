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
  script_id(141793);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-14672", "CVE-2020-14760", "CVE-2020-14765", "CVE-2020-14769", "CVE-2020-14771", "CVE-2020-14773", "CVE-2020-14775", "CVE-2020-14776", "CVE-2020-14777", "CVE-2020-14785", "CVE-2020-14786", "CVE-2020-14789", "CVE-2020-14790", "CVE-2020-14791", "CVE-2020-14793", "CVE-2020-14794", "CVE-2020-14799", "CVE-2020-14800", "CVE-2020-14804", "CVE-2020-14809", "CVE-2020-14812", "CVE-2020-14814", "CVE-2020-14821", "CVE-2020-14827", "CVE-2020-14828", "CVE-2020-14829", "CVE-2020-14830", "CVE-2020-14836", "CVE-2020-14837", "CVE-2020-14838", "CVE-2020-14839", "CVE-2020-14844", "CVE-2020-14845", "CVE-2020-14846", "CVE-2020-14848", "CVE-2020-14852", "CVE-2020-14860", "CVE-2020-14861", "CVE-2020-14866", "CVE-2020-14867", "CVE-2020-14868", "CVE-2020-14869", "CVE-2020-14870", "CVE-2020-14873", "CVE-2020-14878", "CVE-2020-14888", "CVE-2020-14891", "CVE-2020-14893");
  script_xref(name:"IAVA", value:"2020-A-0473-S");

  script_name(english:"FreeBSD : MySQL -- Multiple vulnerabilities (4fba07ca-13aa-11eb-b31e-d4c9ef517024)");
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

This Critical Patch Update contains 48 new security patches for Oracle
MySQL.

The highest CVSS v3.1 Base Score of vulnerabilities affecting Oracle
MySQL is 8.

NOTE: MariaDB only contains CVE-2020-14812 CVE-2020-14765
CVE-2020-14776 and CVE-2020-14789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpuoct2020.html#AppendixMSQL"
  );
  # https://vuxml.freebsd.org/freebsd/4fba07ca-13aa-11eb-b31e-d4c9ef517024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?620f7075"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14878");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb104-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb105-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql80-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb103-server<10.3.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb104-server<10.4.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb105-server<10.5.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.50")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.32")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql80-server<8.0.22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
