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
  script_id(135941);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/18");

  script_cve_id("CVE-2019-1547", "CVE-2019-15601", "CVE-2019-5482", "CVE-2020-2759", "CVE-2020-2760", "CVE-2020-2761", "CVE-2020-2762", "CVE-2020-2763", "CVE-2020-2765", "CVE-2020-2768", "CVE-2020-2770", "CVE-2020-2774", "CVE-2020-2779", "CVE-2020-2780", "CVE-2020-2790", "CVE-2020-2804", "CVE-2020-2806", "CVE-2020-2812", "CVE-2020-2814", "CVE-2020-2853", "CVE-2020-2892", "CVE-2020-2893", "CVE-2020-2895", "CVE-2020-2896", "CVE-2020-2897", "CVE-2020-2898", "CVE-2020-2901", "CVE-2020-2903", "CVE-2020-2904", "CVE-2020-2921", "CVE-2020-2923", "CVE-2020-2924", "CVE-2020-2925", "CVE-2020-2926", "CVE-2020-2928", "CVE-2020-2930");
  script_xref(name:"IAVA", value:"2020-A-0143");

  script_name(english:"FreeBSD : MySQL Server -- Multiple vulerabilities (21d59ea3-8559-11ea-a5e2-d4c9ef517024)");
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

This Critical Patch Update contains 45 new security patches for Oracle
MySQL. 9 of these vulnerabilities may be remotely exploitable without
authentication, i.e., may be exploited over a network without
requiring user credentials.

MariaDB reports 4 of these vulnerabilities exist in their software"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujan2020.html"
  );
  # https://vuxml.freebsd.org/freebsd/21d59ea3-8559-11ea-a5e2-d4c9ef517024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0117443e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb103-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb104-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql80-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona57-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-server<10.2.32")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb103-server<10.3.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb104-server<10.4.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.48")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.30")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql80-server<8.0.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.68")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.48")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona57-server<5.7.30")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
