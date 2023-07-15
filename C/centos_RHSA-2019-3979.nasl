#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3979 and 
# CentOS Errata and Security Advisory 2019:3979 respectively.
#

include('compat.inc');

if (description)
{
  script_id(131571);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-14821", "CVE-2019-15239");
  script_xref(name:"RHSA", value:"2019:3979");

  script_name(english:"CentOS 7 : kernel (CESA-2019:3979)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Kernel: KVM: OOB memory access via mmio ring buffer (CVE-2019-14821)

* kernel: local attacker can trigger multiple use-after-free
conditions results in privilege escalation (CVE-2019-15239)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* On RHEL 7.7 kernel SCSI VPD information for NVMe drives is missing
(breaks InfoScale) (BZ#1752423)

* RHEL7 fnic spamming logs: Current vnic speed set to : 40000
(BZ#1754836)

* kernel build: parallelize redhat/mod-sign.sh (BZ#1755330)

* kernel build: speed up module compression step (BZ#1755339)

* Nested VirtualBox VMs on Windows guest has the potential of
impacting memory region allocated to other KVM guests (BZ#1755781)

* NULL pointer dereference at check_preempt_wakeup+0x109 (BZ#1756265)

* Regression: panic in pick_next_task_rt (BZ#1756267)

* ixgbe reports 'Detected Tx Unit Hang' with adapter reset on RHEL 7
(BZ# 1757350)

* [Intel 7.8 Bug] [KVM][CLX] CPUID_7_0_EDX_ARCH_CAPABILITIES is not
enabled in VM. (BZ#1757757)

* nvme: dead loop in blk_mq_tagset_wait_completed_request() when it is
called from timeout handler (BZ#1758051)

* [mlx5] VF Representer naming is not consistent/persistent through
reboots with OSPD deployment (BZ#1759003)

* OS getting restarted because of driver issue with QLogic Corp.
ISP2532-based 8Gb Fibre Channel to PCI Express HBA [1077:2532] (rev
02). (BZ#1759447)

* mlx5: Load balancing not working over VF LAG configuration
(BZ#1759449)

* RHEL7.8 - ISST-LTE: vimlp1: Running LTP af_alg04.c (crypto) crash
the LPAR (BZ#1763620)

* RHEL7.5 - Fix security issues on crypto vmx (BZ#1763621)

* RHEL 7.7 RC1 - Host crashes about 4.5 hours into switch port bounce
test (BZ#1763624)

* RHEL7.6 - cacheinfo code unsafe vs LPM (BZ#1763625)

* xfs hangs on acquiring xfs_buf semaphore (BZ#1764245)

* single CPU VM hangs during open_posix_testsuite (BZ#1766087)

* rcu_sched self-detected stall on CPU while booting with nohz_full
(BZ# 1766098)");
  # https://lists.centos.org/pipermail/centos-announce/2019-December/023536.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d36315bc");
  # https://lists.centos.org/pipermail/centos-announce/2019-December/035574.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?452de8fb");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15239");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14821");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bpftool-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-1062.7.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-1062.7.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / kernel / kernel-abi-whitelists / kernel-debug / etc");
}
