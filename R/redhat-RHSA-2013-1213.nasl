#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1213. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69795);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4169");
  script_xref(name:"RHSA", value:"2013:1213");

  script_name(english:"RHEL 5 : gdm (RHSA-2013:1213)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdm and initscripts packages that fix one security issue are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The GNOME Display Manager (GDM) provides the graphical login screen,
shown shortly after boot up, log out, and when user-switching.

A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged
user could use this flaw to perform a symbolic link attack, giving
them write access to any file, allowing them to escalate their
privileges to root. (CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the
initscripts package was modified to create the affected directory
safely during the system boot process. Therefore, this update will
appear on all systems, however systems without GDM installed are not
affected by this flaw.

Red Hat would like to thank the researcher with the nickname vladz for
reporting this issue.

All users should upgrade to these updated packages, which correct this
issue. The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4169"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:initscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:initscripts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1213";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gdm-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gdm-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gdm-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gdm-debuginfo-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gdm-debuginfo-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gdm-debuginfo-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gdm-docs-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gdm-docs-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gdm-docs-2.16.0-59.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"initscripts-8.45.42-2.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"initscripts-8.45.42-2.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"initscripts-8.45.42-2.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-debuginfo / gdm-docs / initscripts / etc");
  }
}
