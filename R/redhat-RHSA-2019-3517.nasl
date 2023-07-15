#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3517. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130547);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-1593",
    "CVE-2018-16884",
    "CVE-2018-19854",
    "CVE-2018-19985",
    "CVE-2018-20169",
    "CVE-2019-10126",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-11599",
    "CVE-2019-11833",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-13233",
    "CVE-2019-14821",
    "CVE-2019-15666",
    "CVE-2019-15916",
    "CVE-2019-15921",
    "CVE-2019-15924",
    "CVE-2019-16994",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3874",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-7222",
    "CVE-2019-9506",
    "CVE-2020-11669"
  );
  script_xref(name:"RHSA", value:"2019:3517");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : kernel (RHSA-2019:3517)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: nfs: use-after-free in svc_process_common() (CVE-2018-16884)

* Kernel: vhost_net: infinite loop while receiving packets leads to
DoS (CVE-2019-3900)

* Kernel: page cache side channel attacks (CVE-2019-5489)

* hardware: bluetooth: BR/EDR encryption key negotiation attacks
(KNOB) (CVE-2019-9506)

* kernel: Heap overflow in mwifiex_uap_parse_tail_ies function in
drivers/net /wireless/marvell/mwifiex/ie.c (CVE-2019-10126)

* Kernel: KVM: OOB memory access via mmio ring buffer (CVE-2019-14821)

* kernel: Information Disclosure in crypto_report_one in
crypto/crypto_user.c (CVE-2018-19854)

* kernel: usb: missing size check in the __usb_get_extra_descriptor()
leading to DoS (CVE-2018-20169)

* kernel: Heap address information leak while using L2CAP_GET_CONF_OPT
(CVE-2019-3459)

* kernel: Heap address information leak while using
L2CAP_PARSE_CONF_RSP (CVE-2019-3460)

* kernel: SCTP socket buffer memory leak leading to denial of service
(CVE-2019-3874)

* kernel: denial of service vector through vfio DMA mappings
(CVE-2019-3882)

* kernel: NULL pointer dereference in hci_uart_set_flow_control
(CVE-2019-10207)

* kernel: fix race condition between mmget_not_zero()/get_task_mm()
and core dumping (CVE-2019-11599)

* kernel: fs/ext4/extents.c leads to information disclosure
(CVE-2019-11833)

* kernel: sensitive information disclosure from kernel stack memory
via HIDPCONNADD command (CVE-2019-11884)

* kernel: use-after-free in arch/x86/lib/insn-eval.c (CVE-2019-13233)

* kernel: memory leak in register_queue_kobjects() in
net/core/net-sysfs.c leads to denial of service (CVE-2019-15916)

* kernel: Linux stack ASLR implementation Integer overflow
(CVE-2015-1593)

* kernel: oob memory read in hso_probe in drivers/net/usb/hso.c
(CVE-2018-19985)

* Kernel: KVM: leak of uninitialized stack contents to guest
(CVE-2019-7222)

* Kernel: net: weak IP ID generation leads to remote device tracking
(CVE-2019-10638)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774148ae");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3517");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-1593");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-16884");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-19854");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-19985");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-20169");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3459");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3460");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3874");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3882");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-3900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5489");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7222");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9506");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-10126");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-10207");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-10638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11599");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11833");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11884");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-12382");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13233");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-14821");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-15666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-15916");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-15921");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-15924");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-16994");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2015-1593", "CVE-2018-16884", "CVE-2018-19854", "CVE-2018-19985", "CVE-2018-20169", "CVE-2019-10126", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-11599", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-12382", "CVE-2019-13233", "CVE-2019-14821", "CVE-2019-15666", "CVE-2019-15916", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-16994", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3874", "CVE-2019-3882", "CVE-2019-3900", "CVE-2019-5489", "CVE-2019-7222", "CVE-2019-9506", "CVE-2020-11669");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:3517");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3517";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"bpftool-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"kernel-abi-whitelists-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-core-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-core-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-cross-headers-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-core-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debug-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-extra-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debuginfo-common-aarch64-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"kernel-doc-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-headers-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-extra-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-tools-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-tools-libs-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-core-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-devel-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-extra-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"perf-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-perf-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-debuginfo-4.18.0-147.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-debuginfo-4.18.0-147.el8")) flag++;

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
