#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2863 and 
# CentOS Errata and Security Advisory 2017:2863 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103707);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7541");
  script_xref(name:"RHSA", value:"2017:2863");

  script_name(english:"CentOS 6 : kernel (CESA-2017:2863)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Kernel memory corruption due to a buffer overflow was found in
brcmf_cfg80211_mgmt_tx() function in Linux kernels from v3.9-rc1 to
v4.13-rc1. The vulnerability can be triggered by sending a crafted
NL80211_CMD_FRAME packet via netlink. This flaw is unlikely to be
triggered remotely as certain userspace code is needed for this. An
unprivileged local user could use this flaw to induce kernel memory
corruption on the system, leading to a crash. Due to the nature of the
flaw, privilege escalation cannot be fully ruled out, although it is
unlikely. (CVE-2017-7541, Moderate)

Bug Fix(es) :

* Previously, removal of a rport during ISCSI target scanning could
cause a kernel panic. This was happening because addition of
STARGET_REMOVE to the rport state introduced a race condition to the
SCSI code. This update adds the STARGET_CREATED_REMOVE state as a
possible state of the rport and appropriate handling of that state,
thus fixing the bug. As a result, the kernel panic no longer occurs
under the described circumstances. (BZ# 1472127)

* Previously, GFS2 contained multiple bugs where the wrong inode was
assigned to GFS2 cluster-wide locks (glocks), or the assigned inode
was cleared incorrectly. Consequently, kernel panic could occur when
using GFS2. With this update, GFS2 has been fixed, and the kernel no
longer panics due to those bugs. (BZ#1479397)

* Previously, VMs with memory larger than 64GB running on Hyper-V with
Windows Server hosts reported potential memory size of 4TB and more,
but could not use more than 64GB. This was happening because the
Memory Type Range Register (MTRR) for memory above 64GB was omitted.
With this update, the /proc/mtrr file has been fixed to show correct
base/size if they are more than 44 bit wide. As a result, the whole
size of memory is now available as expected under the described
circumstances. (BZ#1482855)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-October/022564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?826d9e26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7541");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-696.13.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-696.13.2.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
