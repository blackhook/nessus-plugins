#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1218. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40639);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1376", "CVE-2009-2694", "CVE-2009-3025", "CVE-2009-3026");
  script_xref(name:"RHSA", value:"2009:1218");

  script_name(english:"RHEL 3 / 4 / 5 : pidgin (RHSA-2009:1218)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

Federico Muttis of Core Security Technologies discovered a flaw in
Pidgin's MSN protocol handler. If a user received a malicious MSN
message, it was possible to execute arbitrary code with the
permissions of the user running Pidgin. (CVE-2009-2694)

Note: Users can change their privacy settings to only allow messages
from users on their buddy list to limit the impact of this flaw.

These packages upgrade Pidgin to version 2.5.9. Refer to the Pidgin
release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users should upgrade to these updated packages, which
resolve this issue. Pidgin must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-2694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:1218"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1218";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"pidgin-1.5.1-4.el3")) flag++;


  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"finch-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"finch-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"finch-devel-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"finch-devel-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-devel-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-devel-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-perl-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-perl-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-tcl-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-tcl-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"pidgin-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"pidgin-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"pidgin-devel-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"pidgin-devel-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"pidgin-perl-2.5.9-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"pidgin-perl-2.5.9-1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"finch-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"finch-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"finch-devel-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"finch-devel-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-devel-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-devel-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-perl-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-perl-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-tcl-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-tcl-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-devel-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-devel-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-perl-2.5.9-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-perl-2.5.9-1.el5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
  }
}
