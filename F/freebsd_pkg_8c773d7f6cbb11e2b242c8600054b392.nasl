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
  script_id(64421);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-4414", "CVE-2012-5611", "CVE-2012-5612", "CVE-2012-5615", "CVE-2012-5627");

  script_name(english:"FreeBSD : mysql/mariadb/percona server -- multiple vulnerabilities (8c773d7f-6cbb-11e2-b242-c8600054b392)");
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
"ORACLE reports :

Multiple SQL injection vulnerabilities in the replication code

Stack-based buffer overflow

Heap-based buffer overflow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.atlassian.net/browse/MDEV-4029"
  );
  # https://mariadb.atlassian.net/browse/MDEV-MDEV-729
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a50de489"
  );
  # https://mariadb.atlassian.net/browse/MDEV-MDEV-729
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a50de489"
  );
  # http://www.mysqlperformanceblog.com/2013/01/23/announcing-percona-server-5-5-29-29-4/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c5021eb"
  );
  # https://vuxml.freebsd.org/freebsd/8c773d7f-6cbb-11e2-b242-c8600054b392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c62174a0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:percona-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
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

if (pkg_test(save_report:TRUE, pkg:"mysql-server>=5.1<5.1.67")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mysql-server>=5.5<5.5.29")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb-server>=5.3<5.3.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mariadb-server>=5.5<5.5.29")) flag++;
if (pkg_test(save_report:TRUE, pkg:"percona-server>=5.5<5.5.29.29.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
