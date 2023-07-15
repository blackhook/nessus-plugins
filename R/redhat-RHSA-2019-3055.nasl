#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3055. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129958);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2018-20856",
    "CVE-2019-3846",
    "CVE-2019-9506",
    "CVE-2019-10126"
  );
  script_xref(name:"RHSA", value:"2019:3055");

  script_name(english:"RHEL 7 : kernel (RHSA-2019:3055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-20856");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3846");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9506");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-10126");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-20856", "CVE-2019-10126", "CVE-2019-3846", "CVE-2019-9506");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:3055");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3055";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bpftool-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bpftool-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bpftool-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bpftool-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"kernel-abi-whitelists-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-devel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"kernel-doc-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-headers-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perf-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-perf-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-1062.4.1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-1062.4.1.el7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / kernel-abi-whitelists / etc");
  }
}
