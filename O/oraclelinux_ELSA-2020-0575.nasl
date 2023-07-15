#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0575 and 
# Oracle Linux Security Advisory ELSA-2020-0575 respectively.
#

include("compat.inc");

if (description)
{
  script_id(134058);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/15");

  script_cve_id("CVE-2020-1712");
  script_xref(name:"RHSA", value:"2020:0575");

  script_name(english:"Oracle Linux 8 : systemd (ELSA-2020-0575)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2020:0575 :

An update for systemd is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
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

* systemd: use-after-free when asynchronous polkit queries are
performed (CVE-2020-1712)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* systemd: systemctl reload command breaks ordering dependencies
between units (BZ#1781712)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-February/009659.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1712");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-container-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-devel-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-journal-remote-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-libs-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-pam-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-tests-239-18.0.2.el8_1.4")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"systemd-udev-239-18.0.2.el8_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd / systemd-container / systemd-devel / etc");
}
