#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0512 and 
# CentOS Errata and Security Advisory 2019:0512 respectively.
#

include("compat.inc");

if (description)
{
  script_id(122954);
  script_version("1.5");
  script_cvs_date("Date: 2020/02/04");

  script_cve_id("CVE-2018-17972", "CVE-2018-18445", "CVE-2018-9568");
  script_xref(name:"RHSA", value:"2019:0512");

  script_name(english:"CentOS 7 : kernel (CESA-2019:0512)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: Memory corruption due to incorrect socket cloning
(CVE-2018-9568)

* kernel: Unprivileged users able to inspect kernel stacks of
arbitrary tasks (CVE-2018-17972)

* kernel: Faulty computation of numberic bounds in the BPF verifier
(CVE-2018-18445)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) and Enhancement(s) :

* kernel fuse invalidates cached attributes during reads (BZ#1657921)

* [NetApp-FC-NVMe] RHEL7.6: nvme reset gets hung indefinitely
(BZ#1659937)

* Memory reclaim deadlock calling __sock_create() after
memalloc_noio_save() (BZ#1660392)

* hardened usercopy is causing crash (BZ#1660815)

* Backport: xfrm: policy: init locks early (BZ#1660887)

* AWS m5 instance type loses NVMe mounted volumes [was: Unable to
Mount StatefulSet PV in AWS EBS] (BZ#1661947)

* RHEL 7.6 running on a VirtualBox guest with a GUI has a mouse
problem (BZ# 1662848)

* Kernel bug report in cgroups on heavily contested 3.10 node
(BZ#1663114)

* [PCIe] SHPC probe crash on Non-ACPI/Non-SHPC ports (BZ#1663241)

* [Cavium 7.7 Feat] qla2xxx: Update to latest upstream. (BZ#1663508)

* Regression in lpfc and the CNE1000 (BE2 FCoE) adapters that no
longer initialize (BZ#1664067)

* [csiostor] call trace after command: modprobe csiostor (BZ#1665370)

* libceph: fall back to sendmsg for slab pages (BZ#1665814)

* Deadlock between stop_one_cpu_nowait() and stop_two_cpus()
(BZ#1667328)

* Soft lockups occur when the sd driver passes a device size of 1
sector to string_get_size() (BZ#1667989)

* [RHEL7.7] BUG: unable to handle kernel paging request at
ffffffffffffffff (BZ#1668208)

* RHEL7.6 - powerpc/pseries: Disable CPU hotplug across migrations /
powerpc/ rtas: Fix a potential race between CPU-Offline & Migration
(LPM) (BZ# 1669044)

* blk-mq: fix corruption with direct issue (BZ#1670511)

* [RHEL7][patch] iscsi driver can block reboot/shutdown (BZ#1670680)

* [DELL EMC 7.6 BUG] Unable to create-namespace over Dell NVDIMM-N
(BZ# 1671743)

* efi_bgrt_init fails to ioremap error during boot (BZ#1671745)

* Unable to mount a share on kernel- 3.10.0-957.el7. The share can be
mounted on kernel-3.10.0-862.14.4.el7 (BZ#1672448)

* System crash with RIP nfs_readpage_async+0x43 -- BUG: unable to
handle kernel NULL pointer dereference (BZ#1672510)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs and add this enhancement."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-March/023218.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a383377"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18445");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bpftool-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-957.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-957.10.1.el7")) flag++;


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
