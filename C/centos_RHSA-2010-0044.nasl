#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0044 and 
# CentOS Errata and Security Advisory 2010:0044 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44028);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0013");
  script_bugtraq_id(37524);
  script_xref(name:"RHSA", value:"2010:0044");

  script_name(english:"CentOS 4 / 5 : pidgin (CESA-2010:0044)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A directory traversal flaw was discovered in Pidgin's MSN protocol
implementation. A remote attacker could send a specially crafted
emoticon image download request that would cause Pidgin to disclose an
arbitrary file readable to the user running Pidgin. (CVE-2010-0013)

These packages upgrade Pidgin to version 2.6.5. Refer to the Pidgin
release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users should upgrade to these updated packages, which
correct this issue. Pidgin must be restarted for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016447.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8376a035"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016448.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63140d4f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b707cce7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016466.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae998e50"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/15");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"finch-devel-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"finch-devel-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-devel-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-devel-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-perl-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-perl-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpurple-tcl-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpurple-tcl-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-devel-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-devel-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pidgin-perl-2.6.5-1.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pidgin-perl-2.6.5-1.el4.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"finch-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.6.5-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.6.5-1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
