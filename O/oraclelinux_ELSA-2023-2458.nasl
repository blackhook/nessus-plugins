#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2458.
##

include('compat.inc');

if (description)
{
  script_id(175726);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id(
    "CVE-2021-26341",
    "CVE-2021-33655",
    "CVE-2022-1462",
    "CVE-2022-1789",
    "CVE-2022-1882",
    "CVE-2022-2196",
    "CVE-2022-2663",
    "CVE-2022-3028",
    "CVE-2022-3435",
    "CVE-2022-3522",
    "CVE-2022-3524",
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2022-3619",
    "CVE-2022-3623",
    "CVE-2022-3625",
    "CVE-2022-3628",
    "CVE-2022-3640",
    "CVE-2022-3707",
    "CVE-2022-4128",
    "CVE-2022-4129",
    "CVE-2022-20141",
    "CVE-2022-21505",
    "CVE-2022-28388",
    "CVE-2022-33743",
    "CVE-2022-39188",
    "CVE-2022-39189",
    "CVE-2022-41674",
    "CVE-2022-42703",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722",
    "CVE-2022-42896",
    "CVE-2022-43750",
    "CVE-2022-47929",
    "CVE-2023-0394",
    "CVE-2023-0461",
    "CVE-2023-0590",
    "CVE-2023-1195",
    "CVE-2023-1382"
  );

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2023-2458)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2458 advisory.

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier
    assigned to this vulnerability. (CVE-2022-3567)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a
    user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage
    of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read
    unauthorized random data from memory. (CVE-2022-1462)

  - A vulnerability, which was classified as critical, was found in Linux Kernel. Affected is the function
    l2cap_conn_del of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads
    to use after free. It is recommended to apply a patch to fix this issue. The identifier of this
    vulnerability is VDB-211944. (CVE-2022-3640)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - A buffer overflow flaw was found in the Linux kernel Broadcom Full MAC Wi-Fi driver. This issue occurs
    when a user connects to a malicious USB device. This can allow a local user to crash the system or
    escalate their privileges. (CVE-2022-3628)

  - A list management bug in BSS handling in the mac80211 stack in the Linux kernel 5.1 through 5.19.x before
    5.19.16 could be used by local attackers (able to inject WLAN frames) to corrupt a linked list and, in
    turn, potentially execute code. (CVE-2022-42721)

  - An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users
    can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED
    situations. (CVE-2022-39189)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

  - A use-after-free flaw was found in the Linux kernel's pipes functionality in how a user performs
    manipulations with the pipe post_one_notification() after free_pipe_info() that is already called. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-1882)

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - A data race flaw was found in the Linux kernel, between where con is allocated and con->sock is set. This
    issue leads to a NULL pointer dereference when accessing con->sock->sk in net/tipc/topsrv.c in the tipc
    protocol in the Linux kernel. (CVE-2023-1382)

  - A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function
    tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It
    is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this
    vulnerability. (CVE-2022-3566)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - With shadow paging enabled, the INVPCID instruction results in a call to kvm_mmu_invpcid_gva. If INVPCID
    is executed with CR0.PG=0, the invlpg callback is not set and the result is a NULL pointer dereference.
    (CVE-2022-1789)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - Some AMD CPUs may transiently execute beyond unconditional direct branches, which may potentially result
    in data leakage. (CVE-2021-26341)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function l2cap_recv_acldata of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211918 is the
    identifier assigned to this vulnerability. (CVE-2022-3619)

  - In ip_check_mc_rcu of igmp.c, there is a possible use after free due to improper locking. This could lead
    to local escalation of privilege when opening and closing inet sockets with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-112551163References: Upstream kernel (CVE-2022-20141)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - AMD recommends using a software mitigation for this issue, which the kernel is enabling by default. The
    Linux kernel will use the generic retpoline software mitigation, instead of the specialized AMD one, on
    AMD instances (*5a*). This is done by default, and no administrator action is needed. (CVE-2021-26341)
    (CVE-2022-21505)

  - network backend may cause Linux netfront to use freed SKBs While adding logic to support XDP (eXpress Data
    Path), a code label was moved in a way allowing for SKBs having references (pointers) retained for further
    processing to nevertheless be freed. (CVE-2022-33743)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - A NULL pointer dereference issue was discovered in the Linux kernel in the MPTCP protocol when traversing
    the subflow list at disconnect time. A local user could use this flaw to potentially crash the system
    causing a denial of service. (CVE-2022-4128)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - Various refcounting bugs in the multi-BSS handling in the mac80211 stack in the Linux kernel 5.1 through
    5.19.x before 5.19.16 could be used by local attackers (able to inject WLAN frames) to trigger use-after-
    free conditions to potentially execute code. (CVE-2022-42720)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - An issue was discovered in the Linux kernel before 5.19.16. Attackers able to inject WLAN frames could
    cause a buffer overflow in the ieee80211_bss_info_update function in net/mac80211/scan.c. (CVE-2022-41674)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - In the Linux kernel 5.8 through 5.19.x before 5.19.16, local attackers able to inject WLAN frames into the
    mac80211 stack could cause a NULL pointer dereference denial-of-service attack against the beacon
    protection of P2P devices. (CVE-2022-42722)

  - A use-after-free flaw was found in qdisc_graft in net/sched/sch_api.c in the Linux Kernel due to a race
    problem. This flaw leads to a denial of service issue. If patch ebda44da44f6 (net: sched: fix race
    condition in qdisc_graft()) not applied yet, then kernel could be affected. (CVE-2023-0590)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2458.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1882");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-284.11.1.el9_2'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-2458');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.0.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.0.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-284.11.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-debug-uki-virt-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-uki-virt-5.14.0'},
    {'reference':'kernel-devel-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-uki-virt-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-5.14.0'},
    {'reference':'perf-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-284.11.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-284.11.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
