#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175236);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/07");

  script_cve_id(
    "CVE-2022-2196",
    "CVE-2022-3111",
    "CVE-2022-3424",
    "CVE-2022-3707",
    "CVE-2022-4662",
    "CVE-2022-4696",
    "CVE-2022-20568",
    "CVE-2022-41218",
    "CVE-2022-47929",
    "CVE-2022-47946",
    "CVE-2023-0179",
    "CVE-2023-0394",
    "CVE-2023-0590",
    "CVE-2023-20928",
    "CVE-2023-23454",
    "CVE-2023-23455"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2023-1781)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - In (TBD) of (TBD), there is a possible way to corrupt kernel memory due to a use after free. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-220738351References:
    Upstream kernel (CVE-2022-20568)

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - An issue was discovered in the Linux kernel through 5.16-rc6. free_charger_irq() in
    drivers/power/supply/wm8350_power.c lacks free of WM8350_IRQ_CHG_FAST_RDY, which is registered in
    wm8350_init_charger(). (CVE-2022-3111)

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - A flaw incorrect access control in the Linux kernel USB core subsystem was found in the way user attaches
    usb device. A local user could use this flaw to crash the system. (CVE-2022-4662)

  - There exists a use-after-free vulnerability in the Linux kernel through io_uring and the IORING_OP_SPLICE
    operation. If IORING_OP_SPLICE is missing the IO_WQ_WORK_FILES flag, which signals that the operation
    won't use current->nsproxy, so its reference counter is not increased. This assumption is not always true
    as calling io_splice on specific files will call the get_uts function which will use current->nsproxy
    leading to invalidly decreasing its reference counter later causing the use-after-free vulnerability. We
    recommend upgrading to version 5.10.160 or above (CVE-2022-4696)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with 'tc qdisc' and 'tc class' commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - An issue was discovered in the Linux kernel 5.10.x before 5.10.155. A use-after-free in io_sqpoll_wait_sq
    in fs/io_uring.c allows an attacker to crash the kernel, resulting in denial of service. finish_wait can
    be skipped. An attack can occur in some situations by forking a process and then quickly terminating it.
    NOTE: later kernel versions, such as the 5.15 longterm series, substantially changed the implementation of
    io_sqpoll_wait_sq. (CVE-2022-47946)

  - A buffer overflow vulnerability was found in the Netfilter subsystem in the Linux Kernel. This issue could
    allow the leakage of both stack and heap addresses, and potentially allow Local Privilege Escalation to
    the root user via arbitrary code execution. (CVE-2023-0179)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - A use-after-free flaw was found in qdisc_graft in net/sched/sch_api.c in the Linux Kernel due to a race
    problem. This flaw leads to a denial of service issue. If patch ebda44da44f6 ('net: sched: fix race
    condition in qdisc_graft()') not applied yet, then kernel could be affected. (CVE-2023-0590)

  - In binder_vma_close of binder.c, there is a possible use after free due to improper locking. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-254837884References:
    Upstream kernel (CVE-2023-20928)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1781
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa4e16e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20928");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-60.18.0.50.h716.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h716.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h716.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h716.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h716.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h716.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
