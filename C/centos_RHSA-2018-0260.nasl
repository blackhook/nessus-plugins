#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0260 and 
# CentOS Errata and Security Advisory 2018:0260 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106566);
  script_version("3.8");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-1049");
  script_xref(name:"RHSA", value:"2018:0260");

  script_name(english:"CentOS 7 : systemd (CESA-2018:0260)");
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

* A race condition was found in systemd. This could result in
automount requests not being serviced and processes using them could
hang, causing denial of service. (CVE-2018-1049)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-February/022760.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3333da49"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1049");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgudev1-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgudev1-devel-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-devel-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-journal-gateway-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-libs-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-networkd-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-python-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-resolved-219-42.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"systemd-sysv-219-42.el7_4.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / systemd-devel / etc");
}
