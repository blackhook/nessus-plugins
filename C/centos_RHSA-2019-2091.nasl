#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2091 and 
# CentOS Errata and Security Advisory 2019:2091 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128350);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/29");

  script_cve_id("CVE-2018-15686", "CVE-2018-16866", "CVE-2018-16888");
  script_xref(name:"RHSA", value:"2019:2091");

  script_name(english:"CentOS 7 : systemd (CESA-2019:2091)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for systemd is now available for Red Hat Enterprise Linux 7.

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

* systemd: line splitting via fgets() allows for state injection
during daemon-reexec (CVE-2018-15686)

* systemd: out-of-bounds read when parsing a crafted syslog message
(CVE-2018-16866)

* systemd: kills privileged process if unprivileged PIDFile was
tampered (CVE-2018-16888)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95148342"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgudev1-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgudev1-devel-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-devel-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-journal-gateway-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-libs-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-networkd-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-python-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-resolved-219-67.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-sysv-219-67.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / systemd-devel / etc");
}
