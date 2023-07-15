#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176579);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id(
    "CVE-2021-3923",
    "CVE-2022-3707",
    "CVE-2022-4269",
    "CVE-2022-27672",
    "CVE-2022-45934",
    "CVE-2023-0045",
    "CVE-2023-0461",
    "CVE-2023-0590",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1076",
    "CVE-2023-1079",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1380",
    "CVE-2023-1382",
    "CVE-2023-1390",
    "CVE-2023-1582",
    "CVE-2023-26545",
    "CVE-2023-28328",
    "CVE-2023-28466",
    "CVE-2023-28772"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : kernel (EulerOS-SA-2023-2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A flaw was found in the Linux kernel's implementation of RDMA over infiniband. An attacker with a
    privileged local account can leak kernel stack information when issuing commands to the
    /dev/infiniband/rdma_cm device node. While this access is unlikely to leak sensitive user information, it
    can be further used to defeat existing kernel protection mechanisms. (CVE-2021-3923)

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action 'mirred') a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

  - The current implementation of the prctl syscall does not issue an IBPB immediately during the syscall. The
    ib_prctl_set function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL
    MSR on the function __speculation_ctrl_update, but the IBPB is only issued on the next schedule, when the
    TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to
    the prctl syscall. The patch that added the support for the conditional mitigation via prctl
    (ib_prctl_set) dates back to the kernel 4.9.176. We recommend upgrading past commit
    a664ec9158eeddd75121d39c9a0758016097fa96 (CVE-2023-0045)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A use-after-free flaw was found in qdisc_graft in net/sched/sch_api.c in the Linux Kernel due to a race
    problem. This flaw leads to a denial of service issue. If patch ebda44da44f6 ('net: sched: fix race
    condition in qdisc_graft()') not applied yet, then kernel could be affected. (CVE-2023-0590)

  - A memory corruption flaw was found in the Linux kernel's human interface device (HID) subsystem in how a
    user inserts a malicious USB device. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2023-1073)

  - A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may
    occur when a user starts a malicious networking service and someone connects to this service. This could
    allow a local user to starve resources, causing a denial of service. (CVE-2023-1074)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - A flaw was found in the Linux kernel. A use-after-free may be triggered in asus_kbd_backlight_set when
    plugging/disconnecting in a malicious USB device, which advertises itself as an Asus device. Similarly to
    the previous known CVE-2023-25012, but in asus devices, the work_struct may be scheduled by the LED
    controller while the device is disconnecting, triggering a use-after-free on the struct asus_kbd_leds *led
    structure. A malicious USB device may exploit the issue to cause memory corruption with controlled data.
    (CVE-2023-1079)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege
    Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-
    after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this
    vulnerability to elevate its privileges to root. This issue affects Linux Kernel: from 4.14 before git
    commit ee059170b1f7e94e55fa6cadee544e176a6e59c2. (CVE-2023-1281)

  - A slab-out-of-bound read problem was found in brcmf_get_assoc_ies in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux Kernel. This issue could occur
    when assoc_info->req_len data is bigger than the size of the buffer, defined as WL_EXTRA_BUF_MAX, leading
    to a denial of service. (CVE-2023-1380)

  - A data race flaw was found in the Linux kernel, between where con is allocated and con->sock is set. This
    issue leads to a NULL pointer dereference when accessing con->sock->sk in net/tipc/topsrv.c in the tipc
    protocol in the Linux kernel. (CVE-2023-1382)

  - A remote denial of service vulnerability was found in the Linux kernel's TIPC kernel module. The while
    loop in tipc_link_xmit() hits an unknown state while attempting to parse SKBs, which are not in the queue.
    Sending two small UDP packets to a system with a UDP bearer results in the CPU utilization for the system
    to instantly spike to 100%, causing a denial of service condition. (CVE-2023-1390)

  - A race problem was found in fs/proc/task_mmu.c in the memory management sub-component in the Linux kernel.
    This issue may allow a local attacker with user privilege to cause a denial of service. (CVE-2023-1582)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A NULL pointer dereference flaw was found in the az6027 driver in drivers/media/usb/dev-usb/az6027.c in
    the Linux Kernel. The message from user space is not checked properly before transferring into the device.
    This flaw allows a local user to crash the system or potentially cause a denial of service.
    (CVE-2023-28328)

  - do_tls_getsockopt in net/tls/tls_main.c in the Linux kernel through 6.2.6 lacks a lock_sock call, leading
    to a race condition (with a resultant use-after-free or NULL pointer dereference). (CVE-2023-28466)

  - An issue was discovered in the Linux kernel before 5.13.3. lib/seq_buf.c has a seq_buf_putmem_hex buffer
    overflow. (CVE-2023-28772)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?229190b4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28772");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h998.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h998.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h998.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h998.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
