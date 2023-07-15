#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-333-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168270);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-0171",
    "CVE-2022-2308",
    "CVE-2022-2602",
    "CVE-2022-2663",
    "CVE-2022-2905",
    "CVE-2022-2978",
    "CVE-2022-3028",
    "CVE-2022-3061",
    "CVE-2022-3169",
    "CVE-2022-3176",
    "CVE-2022-3303",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3535",
    "CVE-2022-3542",
    "CVE-2022-3543",
    "CVE-2022-3564",
    "CVE-2022-3565",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-3619",
    "CVE-2022-3621",
    "CVE-2022-3623",
    "CVE-2022-3625",
    "CVE-2022-3628",
    "CVE-2022-3629",
    "CVE-2022-3633",
    "CVE-2022-3635",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-4095",
    "CVE-2022-20421",
    "CVE-2022-39190",
    "CVE-2022-39842",
    "CVE-2022-40307",
    "CVE-2022-40768",
    "CVE-2022-41674",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-42703",
    "CVE-2022-42719",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722",
    "CVE-2022-42895",
    "CVE-2022-42896",
    "CVE-2022-43750",
    "CVE-2022-43945"
  );

  script_name(english:"Slackware Linux 15.0 kernel-generic  Multiple Vulnerabilities (SSA:2022-333-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to kernel-generic.");
  script_set_attribute(attribute:"description", value:
"The version of kernel-generic installed on the remote host is prior to 5.15.80 / 5.15.80_smp. It is, therefore, affected
by multiple vulnerabilities as referenced in the SSA:2022-333-01 advisory.

  - A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root
    (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD
    CPU that supports Secure Encrypted Virtualization (SEV). (CVE-2022-0171)

  - In binder_inc_ref_for_node of binder.c, there is a possible way to corrupt memory due to a use after free.
    This could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-239630375References: Upstream kernel (CVE-2022-20421)

  - A flaw was found in vDPA with VDUSE backend. There are currently no checks in VDUSE kernel driver to
    ensure the size of the device config space is in line with the features advertised by the VDUSE userspace
    application. In case of a mismatch, Virtio drivers config read helpers do not initialize the memory
    indirectly passed to vduse_vdpa_get_config() returning uninitialized memory from the stack. This could
    cause undefined behavior or data leaks in Virtio drivers. (CVE-2022-2308)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - A flaw use after free in the Linux kernel NILFS file system was found in the way user triggers function
    security_inode_alloc to fail with following call to function nilfs_mdt_destroy. A local user could use
    this flaw to crash the system or potentially escalate their privileges on the system. (CVE-2022-2978)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - Found Linux Kernel flaw in the i740 driver. The Userspace program could pass any values to the driver
    through ioctl() interface. The driver doesn't check the value of 'pixclock', so it may cause a divide by
    zero error. (CVE-2022-3061)

  - A flaw was found in the Linux kernel. A denial of service flaw may occur if there is a consecutive request
    of the NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
    in a PCIe link disconnect. (CVE-2022-3169)

  - There exists a use-after-free in io_uring in the Linux kernel. Signalfd_poll() and binder_poll() use a
    waitqueue whose lifetime is the current task. It will send a POLLFREE notification to all waiters before
    the queue is freed. Unfortunately, the io_uring poll doesn't handle POLLFREE. This allows a use-after-free
    to occur if a signalfd or binder fd is polled with io_uring poll, and the waitqueue gets freed. We
    recommend upgrading past commit fc78b2fc21f10c4c9c4d5d659a685710ffa63659 (CVE-2022-3176)

  - A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead
    to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
    member of the audio group) could use this flaw to crash the system, resulting in a denial of service
    condition (CVE-2022-3303)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability classified as problematic was found in Linux Kernel. Affected by this vulnerability is the
    function mvpp2_dbgfs_port_init of the file drivers/net/ethernet/marvell/mvpp2/mvpp2_debugfs.c of the
    component mvpp2. The manipulation leads to memory leak. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211033 was assigned to this vulnerability. (CVE-2022-3535)

  - A vulnerability classified as problematic was found in Linux Kernel. This vulnerability affects the
    function bnx2x_tpa_stop of the file drivers/net/ethernet/broadcom/bnx2x/bnx2x_cmn.c of the component BPF.
    The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211042 is
    the identifier assigned to this vulnerability. (CVE-2022-3542)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function unix_sock_destructor/unix_release_sock of the file net/unix/af_unix.c of the component BPF.
    The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. The
    associated identifier of this vulnerability is VDB-211043. (CVE-2022-3543)

  - A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the
    function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated
    identifier of this vulnerability is VDB-211087. (CVE-2022-3564)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function l2cap_recv_acldata of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211918 is the
    identifier assigned to this vulnerability. (CVE-2022-3619)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_bmap_lookup_at_level of the file fs/nilfs2/inode.c of the component nilfs2. The manipulation leads
    to null pointer dereference. It is possible to launch the attack remotely. It is recommended to apply a
    patch to fix this issue. The identifier of this vulnerability is VDB-211920. (CVE-2022-3621)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c of the component IPsec. The manipulation
    leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211930 is the identifier
    assigned to this vulnerability. (CVE-2022-3629)

  - A vulnerability classified as problematic has been found in Linux Kernel. Affected is the function
    j1939_session_destroy of the file net/can/j1939/transport.c of the component IPsec. The manipulation leads
    to memory leak. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability
    is VDB-211932. (CVE-2022-3633)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation
    leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the
    identifier assigned to this vulnerability. (CVE-2022-3635)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

  - An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write in
    drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict of size_t versus int, causing an
    integer overflow and bypassing the size check. After that, because it is used as the third argument to
    copy_from_user(), a heap overflow may occur. (CVE-2022-39842)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

  - An issue was discovered in the Linux kernel before 5.19.16. Attackers able to inject WLAN frames could
    cause a buffer overflow in the ieee80211_bss_info_update function in net/mac80211/scan.c. (CVE-2022-41674)

  - drivers/video/fbdev/smscufx.c in the Linux kernel through 5.19.12 has a race condition and resultant use-
    after-free if a physically proximate attacker removes a USB device while calling open(), aka a race
    condition between ufx_ops_open and ufx_usb_disconnect. (CVE-2022-41849)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - A use-after-free in the mac80211 stack when parsing a multi-BSSID element in the Linux kernel 5.2 through
    5.19.x before 5.19.16 could be used by attackers (able to inject WLAN frames) to crash the kernel and
    potentially execute code. (CVE-2022-42719)

  - Various refcounting bugs in the multi-BSS handling in the mac80211 stack in the Linux kernel 5.1 through
    5.19.x before 5.19.16 could be used by local attackers (able to inject WLAN frames) to trigger use-after-
    free conditions to potentially execute code. (CVE-2022-42720)

  - A list management bug in BSS handling in the mac80211 stack in the Linux kernel 5.1 through 5.19.x before
    5.19.16 could be used by local attackers (able to inject WLAN frames) to corrupt a linked list and, in
    turn, potentially execute code. (CVE-2022-42721)

  - In the Linux kernel 5.8 through 5.19.x before 5.19.16, local attackers able to inject WLAN frames into the
    mac80211 stack could cause a NULL pointer dereference denial-of-service attack against the beacon
    protection of P2P devices. (CVE-2022-42722)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer
    overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send
    buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer
    to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC
    message with garbage data is still correctly formed according to the specification and is passed forward
    to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the
    allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (CVE-2022-43945)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-2602)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected kernel-generic package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.80_smp', 'product' : 'kernel-generic-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.80_smp', 'product' : 'kernel-huge-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.80_smp', 'product' : 'kernel-modules-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.80_smp', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.80_smp', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.80', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
