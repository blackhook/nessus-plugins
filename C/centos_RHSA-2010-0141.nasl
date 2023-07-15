#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0141 and 
# CentOS Errata and Security Advisory 2010:0141 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45067);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-4476", "CVE-2010-0624");
  script_bugtraq_id(26445, 38628);
  script_xref(name:"RHSA", value:"2010:0141");

  script_name(english:"CentOS 4 / 5 : tar (CESA-2010:0141)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated tar package that fixes two security issues is now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GNU tar program saves many files together in one archive and can
restore individual files (or all of the files) from that archive.

A heap-based buffer overflow flaw was found in the way tar expanded
archive files. If a user were tricked into expanding a specially
crafted archive, it could cause the tar executable to crash or execute
arbitrary code with the privileges of the user running tar.
(CVE-2010-0624)

Red Hat would like to thank Jakob Lell for responsibly reporting the
CVE-2010-0624 issue.

A denial of service flaw was found in the way tar expanded archive
files. If a user expanded a specially crafted archive, it could cause
the tar executable to crash. (CVE-2007-4476)

Users of tar are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016558.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af22a263"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f14eb14d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7b5624d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016571.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20b655e9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tar package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"tar-1.14-13.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"tar-1.14-13.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"tar-1.15.1-23.0.1.el5_4.2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tar");
}
