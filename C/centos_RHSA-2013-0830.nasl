#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0830 and 
# CentOS Errata and Security Advisory 2013:0830 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66521);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2013-2094");
  script_xref(name:"RHSA", value:"2013:0830");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/06");

  script_name(english:"CentOS 6 : kernel (CESA-2013:0830)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated kernel packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* It was found that the Red Hat Enterprise Linux 6.1 kernel update
(RHSA-2011:0542) introduced an integer conversion issue in the Linux
kernel's Performance Events implementation. This led to a
user-supplied index into the perf_swevent_enabled array not being
validated properly, resulting in out-of-bounds kernel memory access. A
local, unprivileged user could use this flaw to escalate their
privileges. (CVE-2013-2094, Important)

A public exploit that affects Red Hat Enterprise Linux 6 is available.

Refer to Red Hat Knowledge Solution 373743, linked to in the
References, for further information and mitigation instructions for
users who are unable to immediately apply this update.

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The system must be rebooted
for this update to take effect.");
  # https://lists.centos.org/pipermail/centos-announce/2013-May/019733.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?001479ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-358.6.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-358.6.2.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-devel / kernel-devel / etc");
}
