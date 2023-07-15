#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0348 and 
# CentOS Errata and Security Advisory 2010:0348 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45582);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0436");
  script_bugtraq_id(39467);
  script_xref(name:"RHSA", value:"2010:0348");

  script_name(english:"CentOS 4 / 5 : kdebase (CESA-2010:0348)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdebase packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The K Desktop Environment (KDE) is a graphical desktop environment for
the X Window System. The kdebase packages include core applications
for KDE.

A privilege escalation flaw was found in the KDE Display Manager
(KDM). A local user with console access could trigger a race
condition, possibly resulting in the permissions of an arbitrary file
being set to world-writable, allowing privilege escalation.
(CVE-2010-0436)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for responsibly reporting this issue.

Users of KDE should upgrade to these updated packages, which contain a
backported patch to correct this issue. The system should be rebooted
for this update to take effect. After the reboot, administrators
should manually remove all leftover user-owned dmctl-* directories in
'/var/run/xdmctl/'."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016709.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be8a4efa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016710.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d4837dd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3313043"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-June/016714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faca1c95"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/21");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kdebase-3.3.1-13.el4_8.1.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kdebase-3.3.1-13.el4_8.1.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kdebase-devel-3.3.1-13.el4_8.1.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kdebase-devel-3.3.1-13.el4_8.1.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"kdebase-3.5.4-21.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdebase-devel-3.5.4-21.el5.centos.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-devel");
}
