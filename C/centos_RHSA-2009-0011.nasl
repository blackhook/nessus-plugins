#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0011 and 
# CentOS Errata and Security Advisory 2009:0011 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43725);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-5316", "CVE-2008-5317");
  script_xref(name:"RHSA", value:"2009:0011");

  script_name(english:"CentOS 5 : lcms (CESA-2009:0011)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated lcms packages that resolve several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Little Color Management System (LittleCMS, or simply 'lcms') is a
small-footprint, speed-optimized open source color management engine.

Multiple insufficient input validation flaws were discovered in
LittleCMS. An attacker could use these flaws to create a specially
crafted image file which could cause an application using LittleCMS to
crash, or, possibly, execute arbitrary code when opened.
(CVE-2008-5316, CVE-2008-5317)

Users of lcms should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
using lcms library must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0977ae57"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47a6054b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lcms packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lcms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lcms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-lcms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"lcms-1.15-1.2.2.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"lcms-devel-1.15-1.2.2.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"python-lcms-1.15-1.2.2.el5_2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lcms / lcms-devel / python-lcms");
}
