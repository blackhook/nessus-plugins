#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3055 and 
# CentOS Errata and Security Advisory 2019:3055 respectively.
#

include('compat.inc');

if (description)
{
  script_id(130128);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2018-20856",
    "CVE-2019-3846",
    "CVE-2019-9506",
    "CVE-2019-10126"
  );
  script_xref(name:"RHSA", value:"2019:3055");

  script_name(english:"CentOS 7 : kernel (CESA-2019:3055)");

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

* kernel: Use-after-free in __blk_drain_queue() function in
block/blk-core.c (CVE-2018-20856)

* kernel: Heap overflow in mwifiex_update_bss_desc_with_ie function in
marvell/mwifiex/scan.c (CVE-2019-3846)

* hardware: bluetooth: BR/EDR encryption key negotiation attacks
(KNOB) (CVE-2019-9506)

* kernel: Heap overflow in mwifiex_uap_parse_tail_ies function in
drivers/net /wireless/marvell/mwifiex/ie.c (CVE-2019-10126)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fixes :

* gfs2: Fix iomap write page reclaim deadlock (BZ#1737373)

* [FJ7.6 Bug]: [REG] kernel: ipc: ipc_free should use kvfree
(BZ#1740178)

* high update_cfs_rq_blocked_load contention (BZ#1740180)

* [Hyper-V][RHEL 7] kdump fails to start on a Hyper-V guest of Windows
Server 2019. (BZ#1740188)

* kvm: backport cpuidle-haltpoll driver (BZ#1740192)

* Growing unreclaimable slab memory (BZ#1741920)

* [bnx2x] ping failed from pf to vf which has been attached to vm (BZ#
1741926)

* [Hyper-V]vPCI devices cannot allocate IRQs vectors in a Hyper-V VM
with > 240 vCPUs (i.e., when in x2APIC mode) (BZ#1743324)

* Macsec: inbound MACSEC frame is unexpectedly dropped with
InPktsNotValid (BZ#1744442)

* RHEL 7.7 Beta - Hit error when trying to run nvme connect with IPv6
address (BZ#1744443)

* RHEL 7.6 SS4 - Paths lost when running straight I/O on NVMe/RoCE
system (BZ #1744444)

* NFSv4.0 client sending a double CLOSE (leading to EIO application
failure) (BZ#1744946)

* [Azure] CRI-RDOS | [RHEL 7.8] Live migration only takes 10 seconds,
but the VM was unavailable for 2 hours (BZ#1748239)

* NFS client autodisconnect timer may fire immediately after TCP
connection setup and may cause DoS type reconnect problem in complex
network environments (BZ#1749290)

* [Inspur] RHEL7.6 ASPEED graphic card display issue (BZ#1749296)

* Allows macvlan to operated correctly over the active-backup mode to
support bonding events. (BZ#1751579)

* [LLNL 7.5 Bug] slab leak causing a crash when using kmem control
group (BZ# 1752421)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs.");
  # https://lists.centos.org/pipermail/centos-announce/2019-October/023488.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68dd670d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/22");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bpftool-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-1062.4.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-1062.4.1.el7")) flag++;


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
