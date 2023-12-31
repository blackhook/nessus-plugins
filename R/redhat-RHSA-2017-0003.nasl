#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0003. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96306);
  script_version("1.8");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-7796");
  script_xref(name:"RHSA", value:"2017:0003");

  script_name(english:"RHEL 7 : systemd (RHSA-2017:0003)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for systemd is now available for Red Hat Enterprise Linux
7.1 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The systemd packages contain systemd, a system and service manager for
Linux, compatible with the SysV and LSB init scripts. It provides
aggressive parallelism capabilities, uses socket and D-Bus activation
for starting services, offers on-demand starting of daemons, and keeps
track of processes using Linux cgroups. In addition, it supports
snapshotting and restoring of the system state, maintains mount and
automount points, and implements an elaborate transactional
dependency-based service control logic. It can also work as a drop-in
replacement for sysvinit.

Security Fix(es) :

* A flaw was found in the way systemd handled empty notification
messages. A local attacker could use this flaw to make systemd freeze
its execution, preventing further management of system services,
system shutdown, or zombie process collection via systemd.
(CVE-2016-7796)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:0003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7796"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0003";
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
  if (rpm_check(release:"RHEL7", sp:"1", reference:"libgudev1-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"libgudev1-devel-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"systemd-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"systemd-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"systemd-debuginfo-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"systemd-devel-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"systemd-journal-gateway-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"systemd-journal-gateway-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"systemd-libs-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"systemd-python-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"systemd-python-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"systemd-sysv-208-20.el7_1.9")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"systemd-sysv-208-20.el7_1.9")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / systemd-debuginfo / etc");
  }
}
