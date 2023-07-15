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
  script_id(106216);
  script_version("3.5");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-2562", "CVE-2018-2565", "CVE-2018-2573", "CVE-2018-2576", "CVE-2018-2583", "CVE-2018-2586", "CVE-2018-2590", "CVE-2018-2591", "CVE-2018-2600", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2645", "CVE-2018-2646", "CVE-2018-2647", "CVE-2018-2665", "CVE-2018-2667", "CVE-2018-2668", "CVE-2018-2696", "CVE-2018-2703");

  script_name(english:"FreeBSD : MySQL -- multiple vulnerabilities (e3445736-fd01-11e7-ac58-b499baebfeaf)");
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

Not all vulnerabilities are relevant for all flavors/versions of the
servers and clients

- Vulnerability allows low privileged attacker with network access via
multiple protocols to compromise MySQL Server. Successful attacks of
this vulnerability can result in unauthorized ability to cause a hang
or frequently repeatable crash (complete DOS) of MySQL Server. GIS:
CVE-2018-2573, DDL CVE-2018-2622, Optimizer: CVE-2018-2640,
CVE-2018-2665, CVE-2018-2668, Security:Privileges: CVE-2018-2703,
Partition: CVE-2018-2562.

- Vulnerability allows high privileged attacker with network access
via multiple protocols to compromise MySQL Server. Successful attacks
of this vulnerability can result in unauthorized ability to cause a
hang or frequently repeatable crash (complete DOS) of MySQL Server.
InnoDB: CVE-2018-2565, CVE-2018-2612 DML: CVE-2018-2576,
CVE-2018-2646, Stored Procedure: CVE-2018-2583, Performance Schema :
CVE-2018-2590, Partition: CVE-2018-2591, Optimizer: CVE-2018-2600,
CVE-2018-2667, Security:Privileges: CVE-2018-2696, Replication :
CVE-2018-2647.

- Vulnerability allows a low or high privileged attacker with network
access via multiple protocols to compromise MySQL Server with
unauthorized creation, deletion, modification or access to data/
critical data. InnoDB: CVE-2018-2612, Performance Schema :
CVE-2018-2645, Replication: CVE-2018-2647, Partition: CVE-2018-2562."
  );
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixMSQL
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db190281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-5559-release-notes/"
  );
  # https://vuxml.freebsd.org/freebsd/e3445736-fd01-11e7-ac58-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?852ea270"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb100-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb101-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb102-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql57-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona56-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona57-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"mariadb55-server<5.5.59")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb100-server<10.0.34")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb101-server<10.1.31")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb102-server<10.2.13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql55-server<5.5.59")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql56-server<5.6.39")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql57-server<5.7.21")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona55-server<5.5.59")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona56-server<5.6.39")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona57-server<5.7.21")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
