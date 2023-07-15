#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0717 and 
# CentOS Errata and Security Advisory 2019:0717 respectively.
#

include("compat.inc");

if (description)
{
  script_id(124035);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-13405");
  script_xref(name:"RHSA", value:"2019:0717");

  script_name(english:"CentOS 6 : kernel (CESA-2019:0717)");
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
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: Missing check in fs/inode.c:inode_init_owner() does not
clear SGID bit on non-directories for non-members (CVE-2018-13405)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* sched/sysctl: Check user input value of sysctl_sched_time_avg
(BZ#1579128)

* unable to handle kernel NULL pointer dereference at 000000000000005d
in tcp_enter_frto+0x102 (BZ#1585892)

* qla2xxx: Mask Off Scope bits for Retry delay timer in the driver
(BZ# 1588133)

* [PATCH] perf: Fix a race between ring_buffer_detach() and
ring_buffer_wakeup() (BZ#1589340)

* RHEL6.10 - kernel: improve spectre mitigation for s390x (BZ#1625381)

* kernel panic due to NULL pointer dereference in __wake_up_common
through perf_event_wakeup (BZ#1627672)

* After upgrading from rhel 6.9 to rhel 6.10, files in a cifs share
can't be read (BZ#1636484)

* Retpoline impact on vdso gettimeofday performance (BZ#1638552)

* [RHEL 6.10] 32-bit kernel-2.6.32-754.3.5 registers the swap of 4k
size only (BZ#1670328)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-April/023265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bf6985c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13405");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-754.12.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-754.12.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
