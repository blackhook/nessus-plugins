#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1083 and 
# Oracle Linux Security Advisory ELSA-2015-1083 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84074);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3150", "CVE-2015-3151", "CVE-2015-3159", "CVE-2015-3315");
  script_bugtraq_id(75116, 75117, 75118, 75119, 75122, 75124, 75128, 75129);
  script_xref(name:"RHSA", value:"2015:1083");

  script_name(english:"Oracle Linux 7 : abrt (ELSA-2015-1083)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1083 :

Updated abrt packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

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
this flaw to expose other parts of ABRT to attack, or to overwrite
arbitrary files on the system. (CVE-2015-3147)

Multiple directory traversal flaws were found in the abrt-dbus D-Bus
service. A local attacker could use these flaws to read and write
arbitrary files as the root user. (CVE-2015-3151)

It was discovered that the abrt-dbus D-Bus service did not properly
check the validity of the problem directory argument in the
ChownProblemDir, DeleteElement, and DeleteProblem methods. A local
attacker could use this flaw to take ownership of arbitrary files and
directories, or to delete files and directories as the root user.
(CVE-2015-3150)

It was discovered that the abrt-action-install-debuginfo-to-abrt-cache
helper program did not properly filter the process environment before
invoking abrt-action-install-debuginfo. A local attacker could use
this flaw to escalate their privileges on the system. (CVE-2015-3159)

All users of abrt are advised to upgrade to these updated packages,
which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-June/005106.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected abrt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ABRT raceabrt Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-pstoreoops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-upload-watch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-addon-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-console-notification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-gui-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-python-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-retrace-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-rhel-anaconda-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-rhel-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-web-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-ccpp-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-pstoreoops-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-python-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-upload-watch-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-vmcore-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-addon-xorg-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-cli-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-console-notification-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-dbus-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-desktop-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-devel-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-gui-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-gui-devel-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-gui-libs-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-libs-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-python-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-python-doc-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-retrace-client-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"abrt-tui-2.1.11-22.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-anaconda-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-cli-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-compat-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-devel-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-filesystem-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-gtk-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-gtk-devel-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-newt-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-plugin-logger-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-plugin-mailx-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-plugin-ureport-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-python-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-rhel-anaconda-bugzilla-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-rhel-bugzilla-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-web-2.1.11-23.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreport-web-devel-2.1.11-23.0.1.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / etc");
}
