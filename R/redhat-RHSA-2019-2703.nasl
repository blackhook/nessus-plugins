#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2703. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128665);
  script_version("1.6");
  script_cvs_date("Date: 2020/01/30");

  script_cve_id("CVE-2018-19824", "CVE-2019-11487", "CVE-2019-12817", "CVE-2019-3846", "CVE-2019-3887", "CVE-2019-9500", "CVE-2019-9503");
  script_xref(name:"RHSA", value:"2019:2703");

  script_name(english:"RHEL 8 : kernel (RHSA-2019:2703)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: Heap overflow in mwifiex_update_bss_desc_with_ie function in
marvell/mwifiex/scan.c (CVE-2019-3846)

* Kernel: KVM: nVMX: guest accesses L0 MSR causes potential DoS
(CVE-2019-3887)

* kernel: brcmfmac heap buffer overflow in brcmf_wowl_nd_results
(CVE-2019-9500)

* kernel: Count overflow in FUSE request leading to use-after-free
issues. (CVE-2019-11487)

* kernel: ppc: unrelated processes being able to read/write to each
other's virtual memory (CVE-2019-12817)

* kernel: Use-after-free in sound/usb/card.c:usb_audio_probe()
(CVE-2018-19824)

* kernel: brcmfmac frame validation bypass (CVE-2019-9503)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* [DELL EMC 8.0 BUG]: pciehp deadlock resulting in NVMe device not
being recognized when hot plugged (BZ#1712261)

* Host crashed while try to boot a compatible guest attached huge page
by'-object memory-backend-file *'[1G-P9] (BZ#1714758)

* Setting malformed authenc key will crash the system (BZ#1715335)

* BUG: memory allocation failure in
inode_doinit_with_dentry()/context_to_sid () (BZ#1717780)

* [HPEMC 8.1 BUG] Protect against concurrent calls into UV BIOS
(BZ#1724534)

* PHC jumping on I350 (igb) (BZ#1726352)

* aarch64 kernel missing vulnerabilities status files (BZ#1726353)

* BUG: KASAN: use-after-free in skb_release_data() (BZ#1726354)

* [RHEL8][PANIC][aarch64] kernel panic when loading the dme1737 module
(BZ# 1726355)

* [RHEL8] [aarch64] Changes for BZ1672997 break kaslr (BZ#1726357)

* Network fails to come up when booting with kernel
3.10.0-862.el7.x86_64, several hung tasks can be seen in logs.
(BZ#1726358)

* [Intel] 'cpupower frequency-set' produces unexpected results for
some processors (BZ#1726360)

* HDMI/DP audio: ELD not updated on hotplug event (BZ#1726361)

* [mlx5_core] CX5 Adapter works not as expected when MTU is 9000,
Unable to handle kernel paging request at virtual address
3ae0aafeff4b6b5a (BZ# 1726372)

* [DELL 8.0 Bug] - hid-multitouch 0018:1FD2:8008.0001 ,lost function
from S3 resume (BZ#1727098)

* [RHEL8.1 Pre Beta] [Power8] data corruption while returning from
watchpoint exception handler (BZ#1733281)

* RHEL8.1 pre-Beta - cacheinfo code unsafe vs LPM (BZ#1733282)

* RHEL8.1 pre-Beta - [ZZ/Zeppelin] [kernel-4.18.0-100.el8.ppc64le]
Hash MMU allows child to write parents process address space
(BZ#1734689)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-19824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-9500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-9503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-12817"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-19824", "CVE-2019-11487", "CVE-2019-12817", "CVE-2019-3846", "CVE-2019-3887", "CVE-2019-9500", "CVE-2019-9503");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:2703");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2703";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"bpftool-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", reference:"kernel-abi-whitelists-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-core-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-core-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-cross-headers-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-core-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"kernel-debug-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-extra-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"kernel-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"kernel-debuginfo-common-aarch64-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", reference:"kernel-doc-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-headers-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-extra-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"kernel-tools-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"kernel-tools-libs-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-core-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-devel-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-extra-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"perf-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"python3-perf-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-debuginfo-4.18.0-80.11.1.el8_0")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-debuginfo-4.18.0-80.11.1.el8_0")) flag++;


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
