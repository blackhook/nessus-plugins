#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1210. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84609);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3159", "CVE-2015-3315");
  script_bugtraq_id(75116, 75117, 75118, 75119, 75128, 75129);
  script_xref(name:"RHSA", value:"2015:1210");

  script_name(english:"RHEL 6 : abrt (RHSA-2015:1210)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated abrt packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality.

It was found that ABRT was vulnerable to multiple race condition and
symbolic link flaws. A local attacker could use these flaws to
potentially escalate their privileges on the system. (CVE-2015-3315)

It was discovered that the kernel-invoked coredump processor provided
by ABRT wrote core dumps to files owned by other system users. This
could result in information disclosure if an application crashed while
its current directory was a directory writable to by other users (such
as /tmp). (CVE-2015-3142)

It was discovered that the default event handling scripts installed by
ABRT did not handle symbolic links correctly. A local attacker with
write access to an ABRT problem directory could use this flaw to
escalate their privileges. (CVE-2015-1869)

It was found that the ABRT event scripts created a user-readable copy
of an sosreport file in ABRT problem directories, and included
excerpts of /var/log/messages selected by the user-controlled process
name, leading to an information disclosure. (CVE-2015-1870)

It was discovered that, when moving problem reports between certain
directories, abrt-handle-upload did not verify that the new problem
directory had appropriate permissions and did not contain symbolic
links. An attacker able to create a crafted problem report could use
this flaw to expose other parts of ABRT, or to overwrite arbitrary
files on the system. (CVE-2015-3147)

It was discovered that the abrt-action-install-debuginfo-to-abrt-cache
helper program did not properly filter the process environment before
invoking abrt-action-install-debuginfo. A local attacker could use
this flaw to escalate their privileges on the system. (CVE-2015-3159)

The CVE-2015-1869, CVE-2015-1870, CVE-2015-3142, CVE-2015-3147, and
CVE-2015-3159 issues were discovered by Florian Weimer of Red Hat
Product Security.

All users of abrt are advised to upgrade to these updated packages,
which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-3159"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ABRT raceabrt Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-console-notification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1210";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-ccpp-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-ccpp-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-ccpp-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-kerneloops-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-kerneloops-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-python-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-python-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-python-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-vmcore-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-vmcore-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-vmcore-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-cli-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-cli-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-cli-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-console-notification-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-console-notification-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-console-notification-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-debuginfo-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-desktop-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-desktop-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-desktop-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-devel-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-gui-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-gui-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-gui-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-libs-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-python-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-tui-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-tui-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-tui-2.0.8-26.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-cli-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-cli-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-cli-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-compat-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-compat-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-compat-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-debuginfo-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-devel-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-filesystem-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-filesystem-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-filesystem-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-gtk-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-gtk-devel-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-newt-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-newt-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-newt-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-bugzilla-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-bugzilla-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-kerneloops-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-kerneloops-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-logger-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-logger-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-logger-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-mailx-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-mailx-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-mailx-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-reportuploader-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-reportuploader-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-rhtsupport-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-rhtsupport-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-python-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-python-2.0.9-21.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-python-2.0.9-21.el6_6.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / abrt-addon-python / etc");
  }
}
