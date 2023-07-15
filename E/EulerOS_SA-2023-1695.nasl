#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175229);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/08");

  script_cve_id(
    "CVE-2021-4155",
    "CVE-2021-4159",
    "CVE-2021-4197",
    "CVE-2021-4203",
    "CVE-2021-33061",
    "CVE-2021-33655",
    "CVE-2021-33656",
    "CVE-2021-39698",
    "CVE-2021-39713",
    "CVE-2021-45868",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0322",
    "CVE-2022-0492",
    "CVE-2022-0494",
    "CVE-2022-0617",
    "CVE-2022-0812",
    "CVE-2022-0850",
    "CVE-2022-0854",
    "CVE-2022-1011",
    "CVE-2022-1012",
    "CVE-2022-1016",
    "CVE-2022-1184",
    "CVE-2022-1353",
    "CVE-2022-1462",
    "CVE-2022-1729",
    "CVE-2022-2503",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-2639",
    "CVE-2022-2663",
    "CVE-2022-2964",
    "CVE-2022-2977",
    "CVE-2022-3028",
    "CVE-2022-3524",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3565",
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-3629",
    "CVE-2022-4129",
    "CVE-2022-20008",
    "CVE-2022-20132",
    "CVE-2022-20154",
    "CVE-2022-20166",
    "CVE-2022-20368",
    "CVE-2022-20565",
    "CVE-2022-23960",
    "CVE-2022-26966",
    "CVE-2022-27666",
    "CVE-2022-28388",
    "CVE-2022-28390",
    "CVE-2022-29581",
    "CVE-2022-30594",
    "CVE-2022-32250",
    "CVE-2022-32296",
    "CVE-2022-34918",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-39188",
    "CVE-2022-41850",
    "CVE-2022-41858",
    "CVE-2022-42703",
    "CVE-2022-42895",
    "CVE-2022-43750"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.0 : kernel (EulerOS-SA-2023-1695)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2021-33061)

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - When setting font with malicous data by ioctl cmd PIO_FONT,kernel will write memory out of bounds.
    (CVE-2021-33656)

  - In aio_poll_complete_work of aio.c, there is a possible memory corruption due to a use after free. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-185125206References: Upstream kernel (CVE-2021-39698)

  - Product: AndroidVersions: Android kernelAndroid ID: A-173788806References: Upstream kernel
    (CVE-2021-39713)

  - A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

  - A vulnerability was found in the Linux kernel's EBPF verifier when handling internal data structures.
    Internal memory locations could be returned to userspace. A local attacker with the permissions to insert
    eBPF code to the kernel can use this to leak internal kernel memory details defeating some of the exploit
    mitigations in place for the kernel. (CVE-2021-4159)

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
    SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a
    user privileges may crash the system or leak internal kernel information. (CVE-2021-4203)

  - In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota
    tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a
    corrupted quota file. (CVE-2021-45868)

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - A flaw was found in the sctp_make_strreset_req function in net/sctp/sm_make_chunk.c in the SCTP network
    protocol in the Linux kernel with a local user privilege access. In this flaw, an attempt to use more
    buffer than is allocated triggers a BUG_ON issue, leading to a denial of service (DOS). (CVE-2022-0322)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - An information leak flaw was found in NFS over RDMA in the net/sunrpc/xprtrdma/rpc_rdma.c in the Linux
    Kernel. This flaw allows an attacker with normal user privileges to leak kernel information.
    (CVE-2022-0812)

  - A vulnerability was found in linux kernel, where an information leak occurs via ext4_extent_header to
    userspace. (CVE-2022-0850)

  - A memory leak flaw was found in the Linux kernel's DMA subsystem, in the way a user calls DMA_FROM_DEVICE.
    This flaw allows a local user to read random memory from the kernel space. (CVE-2022-0854)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a
    use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel
    information leak problem caused by a local, unprivileged attacker. (CVE-2022-1016)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a
    user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage
    of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read
    unauthorized random data from memory. (CVE-2022-1462)

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - In mmc_blk_read_single of block.c, there is a possible way to read kernel heap memory due to uninitialized
    data. This could lead to local information disclosure if reading from an SD card that triggers errors,
    with no additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID: A-216481035References: Upstream kernel (CVE-2022-20008)

  - In lg_probe and related functions of hid-lg.c and other USB HID files, there is a possible out of bounds
    read due to improper input validation. This could lead to local information disclosure if a malicious USB
    HID device were plugged in, with no additional execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-188677105References: Upstream
    kernel (CVE-2022-20132)

  - In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead
    to local escalation of privilege with System execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream
    kernel (CVE-2022-20154)

  - In various methods of kernel base drivers, there is a possible out of bounds write due to a heap buffer
    overflow. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-182388481References: Upstream kernel (CVE-2022-20166)

  - Product: AndroidVersions: Android kernelAndroid ID: A-224546354References: Upstream kernel
    (CVE-2022-20368)

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to
    restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently
    allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass
    verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and
    unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for
    peripherals that do not verify firmware updates. We recommend upgrading past commit
    4caae58406f8ceb741603eee460d79bacca9b1b5 (CVE-2022-2503)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

  - A flaw was found in the Linux kernel implementation of proxied virtualized TPM devices. On a system where
    virtualized TPM devices are configured (this is not the default) a local attacker can create a use-after-
    free and create a situation where it may be possible to escalate privileges on the system. (CVE-2022-2977)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. This occurs because of use of Algorithm 4 ('Double-Hash Port Selection Algorithm') of RFC 6056.
    (CVE-2022-32296)

  - An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init
    (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different
    vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an
    unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data
    in net/netfilter/nf_tables_api.c. (CVE-2022-34918)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function
    tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It
    is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this
    vulnerability. (CVE-2022-3566)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier
    assigned to this vulnerability. (CVE-2022-3567)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this
    vulnerability. (CVE-2022-3629)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in
    progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to
    crash the system or leak internal kernel information. (CVE-2022-41858)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - A vulnerability classified as critical was found in Linux Kernel (Operating System) (affected version
    unknown). Affected by this vulnerability is some unknown processing of the component Cache Handler. There
    is no information about possible countermeasures known. It may be suggested to replace the affected object
    with an alternative product. (CVE-2022-20565)

  - kernel: nf_tables cross-table potential use-after-free may lead to local privilege escalation
    (CVE-2022-2586)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1695
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67df3f9f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34918");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.36-vhulk1907.1.0.h1380",
  "kernel-devel-4.19.36-vhulk1907.1.0.h1380",
  "kernel-headers-4.19.36-vhulk1907.1.0.h1380",
  "kernel-tools-4.19.36-vhulk1907.1.0.h1380",
  "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1380",
  "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h1380",
  "perf-4.19.36-vhulk1907.1.0.h1380",
  "python-perf-4.19.36-vhulk1907.1.0.h1380"
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
