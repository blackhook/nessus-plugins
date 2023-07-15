#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144831);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id(
    "CVE-2014-8181",
    "CVE-2018-14625",
    "CVE-2018-9363",
    "CVE-2019-0136",
    "CVE-2019-10126",
    "CVE-2019-10142",
    "CVE-2019-10639",
    "CVE-2019-11085",
    "CVE-2019-1125",
    "CVE-2019-11486",
    "CVE-2019-11599",
    "CVE-2019-12818",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14901",
    "CVE-2019-15099",
    "CVE-2019-15239",
    "CVE-2019-15292",
    "CVE-2019-15505",
    "CVE-2019-15917",
    "CVE-2019-15926",
    "CVE-2019-15927",
    "CVE-2019-16413",
    "CVE-2019-16746",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2019-18675",
    "CVE-2019-19060",
    "CVE-2019-19074",
    "CVE-2019-19078",
    "CVE-2019-19768",
    "CVE-2019-20636",
    "CVE-2019-3846",
    "CVE-2019-9500",
    "CVE-2019-9503",
    "CVE-2019-9506",
    "CVE-2020-0009",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10757",
    "CVE-2020-10942",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-12654",
    "CVE-2020-13974",
    "CVE-2020-15393",
    "CVE-2020-16166",
    "CVE-2020-24394",
    "CVE-2020-25211",
    "CVE-2020-25212",
    "CVE-2020-25643",
    "CVE-2020-7053",
    "CVE-2020-9383"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.6 : kernel (EulerOS-SA-2021-1056)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw that allowed an attacker to corrupt memory and
    possibly escalate privileges was found in the mwifiex
    kernel module while connecting to a malicious wireless
    network(CVE-2019-3846)

  - An issue was discovered in the Linux kernel before
    5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero
    endpoints(CVE-2020-11608)

  - In the Linux kernel before 5.5.8, get_raw_socket in
    drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel
    stack corruption via crafted system
    calls.(CVE-2020-10942)

  - An issue was discovered in the stv06xx subsystem in the
    Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)

  - An out-of-bounds write flaw was found in the Linux
    kernel. A crafted keycode table could be used by
    drivers/input/input.c to perform the out-of-bounds
    write. A local user with root access can insert garbage
    to this keycode table that can lead to out-of-bounds
    memory access. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as system availability.(CVE-2019-20636)

  - The kernel in Red Hat Enterprise Linux 7 and MRG-2 does
    not clear garbage data for SG_IO buffer, which may
    leaking sensitive information to
    userspace.(CVE-2014-8181)

  - A flaw was found in the Linux kernels SELinux LSM hook
    implementation before version 5.7, where it incorrectly
    assumed that an skb would only contain a single netlink
    message. The hook would incorrectly only validate the
    first netlink message in the skb and allow or deny the
    rest of the messages within the skb with the granted
    permission without further processing.(CVE-2020-10751)

  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information
    Disclosure Vulnerability'.(CVE-2019-1125)

  - A memory leak in the ath10k_usb_hif_tx_sg() function in
    drivers/net/wireless/ath/ath10k/usb.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    usb_submit_urb() failures, aka
    CID-b8d17e7d93d2.(CVE-2019-19078)

  - A flaw was found in the Linux kernel's implementation
    of Userspace core dumps. This flaw allows an attacker
    with a local account to crash a trivial program and
    exfiltrate private kernel data.(CVE-2020-10732)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the
    NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL
    support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered.(CVE-2020-24394)

  - The Linux kernel through 5.7.11 allows remote attackers
    to make observations that help to obtain sensitive
    information about the internal state of the network
    RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and
    kernel/time/timer.c.(CVE-2020-16166)

  - In the Linux kernel through 5.8.7, local attackers able
    to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering
    use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in
    net/netfilter/nf_conntrack_netlink.c, aka
    CID-1cc5ef91d2ff.(CVE-2020-25211)

  - In calc_vm_may_flags of ashmem.c, there is a possible
    arbitrary write to shared memory due to a permissions
    bypass. This could lead to local escalation of
    privilege by corrupting memory shared between
    processes, with no additional execution privileges
    needed. User interaction is not needed for
    exploitation. Product: Android Versions: Android kernel
    Android ID: A-142938932(CVE-2020-0009)

  - In the Linux kernel through 5.7.6, usbtest_disconnect
    in drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770.(CVE-2020-15393)

  - In the Linux kernel before 5.6.1,
    drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink
    camera USB driver) mishandles invalid descriptors, aka
    CID-a246b4d54770.(CVE-2020-11668)

  - An issue was found in Linux kernel before 5.5.4.
    mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a
    remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka
    CID-3a9b153c5591.(CVE-2020-12654)

  - An issue was discovered in the Linux kernel through
    5.7.1. drivers/tty/vt/keyboard.c has an integer
    overflow if k_ascii is called several times in a row,
    aka CID-b86dab054059. NOTE: Members in the community
    argue that the integer overflow does not lead to a
    security issue in this case.(CVE-2020-13974)

  - Insufficient input validation in Kernel Mode Driver in
    Intel(R) i915 Graphics for Linux before version 5.0 may
    allow an authenticated user to potentially enable
    escalation of privilege via local
    access.(CVE-2019-11085)

  - In the hidp_process_report in bluetooth, there is an
    integer overflow. This could lead to an out of bounds
    write with no additional execution privileges needed.
    User interaction is not needed for exploitation.
    Product: Android Versions: Android kernel Android ID:
    A-65853588 References: Upstream kernel.(CVE-2018-9363)

  - A flaw was found in the way mremap handled DAX Huge
    Pages. This flaw allows a local attacker with access to
    a DAX enabled storage to escalate their privileges on
    the system.(CVE-2020-10757)

  - A flaw was found in the Linux kernel. A heap based
    buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead
    to memory corruption and possibly other
    consequences.(CVE-2019-10126)

  - A flaw was found in the HDLC_PPP module of the Linux
    kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input
    validation in the ppp_cp_parse_cr function which can
    cause the system to crash or cause a denial of service.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25643)

  - A TOCTOU mismatch in the NFS client code in the Linux
    kernel before 5.8.3 could be used by local attackers to
    corrupt memory or possibly have unspecified other
    impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka
    CID-b4487b935452.(CVE-2020-25212)

  - In the Linux kernel before 5.7.8, fs/nfsd/vfs.c (in the
    NFS server) can set incorrect permissions on new
    filesystem objects when the filesystem lacks ACL
    support, aka CID-22cf8419f131. This occurs because the
    current umask is not considered.(CVE-2020-24394)

  - A heap overflow flaw was found in the Linux kernel, all
    versions 3.x.x and 4.x.x before 4.18.0, in Marvell WiFi
    chip driver. The vulnerability allows a remote attacker
    to cause a system crash, resulting in a denial of
    service, or execute arbitrary code. The highest threat
    with this vulnerability is with the availability of the
    system. If code execution occurs, the code will run
    with the permissions of root. This will affect both
    confidentiality and integrity of files on the
    system.(CVE-2019-14901)

  - A heap-based buffer overflow vulnerability was found in
    the Linux kernel, version kernel-2.6.32, in Marvell
    WiFi chip driver. A remote attacker could cause a
    denial of service (system crash) or, possibly execute
    arbitrary code, when the lbs_ibss_join_existing
    function is called after a STA connects to an
    AP.(CVE-2019-14896)

  - rtl_p2p_noa_ie in
    drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux
    kernel through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer overflow.(CVE-2019-17666)

  - The Broadcom brcmfmac WiFi driver prior to commit
    a4176ec356c73a46c07c181c6d04039fafa34a9f is vulnerable
    to a frame validation bypass. If the brcmfmac driver
    receives a firmware event frame from a remote source,
    the is_wlc_event_frame function will cause this frame
    to be discarded and unprocessed. If the driver receives
    the firmware event frame from the host, the appropriate
    handler is called. This frame validation can be
    bypassed if the bus used is USB (for instance by a wifi
    dongle). This can allow firmware event frames from a
    remote source to be processed. In the worst case
    scenario, by sending specially-crafted WiFi packets, a
    remote, unauthenticated attacker may be able to execute
    arbitrary code on a vulnerable system. More typically,
    this vulnerability will result in denial-of-service
    conditions.(CVE-2019-9503)

  - An issue was discovered in the Linux kernel before
    5.0.4. The 9p filesystem did not protect i_size_write()
    properly, which causes an i_size_read() infinite loop
    and denial of service on SMP systems.(CVE-2019-16413)

  - An issue was discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance.(CVE-2019-17075)

  - drivers/net/wireless/ath/ath10k/usb.c in the Linux
    kernel through 5.2.8 has a NULL pointer dereference via
    an incomplete address in an endpoint
    descriptor.(CVE-2019-15099)

  - A flaw was found in the Linux kernel's freescale
    hypervisor manager implementation, kernel versions
    5.0.x up to, excluding 5.0.17. A parameter passed to an
    ioctl was incorrectly validated and used in size
    calculations for the page size calculation. An attacker
    can use this flaw to crash the system, corrupt memory,
    or create other adverse security
    affects.(CVE-2019-10142)

  - The Broadcom brcmfmac WiFi driver prior to commit
    1b5e2423164b3670e8bc9174e4762d297990deff is vulnerable
    to a heap buffer overflow. If the Wake-up on Wireless
    LAN functionality is configured, a malicious event
    frame can be constructed to trigger an heap buffer
    overflow in the brcmf_wowl_nd_results function. This
    vulnerability can be exploited with compromised
    chipsets to compromise the host, or when used in
    combination with CVE-2019-9503, can be used remotely.
    In the worst case scenario, by sending
    specially-crafted WiFi packets, a remote,
    unauthenticated attacker may be able to execute
    arbitrary code on a vulnerable system. More typically,
    this vulnerability will result in denial-of-service
    conditions.(CVE-2019-9500)

  - In the Linux kernel 4.14 longterm through 4.14.165 and
    4.19 longterm through 4.19.96 (and 5.x before 5.2),
    there is a use-after-free (write) in the
    i915_ppgtt_close function in
    drivers/gpu/drm/i915/i915_gem_gtt.c, aka
    CID-7dc40713618c. This is related to
    i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c.(CVE-2020-7053)

  - A flaw was found in the Linux Kernel where an attacker
    may be able to have an uncontrolled read to
    kernel-memory from within a vm guest. A race condition
    between connect() and close() function may allow an
    attacker using the AF_VSOCK protocol to gather a 4 byte
    information leak or possibly intercept or corrupt
    AF_VSOCK messages destined to other
    clients.(CVE-2018-14625)

  - An issue was discovered in the Linux kernel before
    5.0.5. There is a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto()
    in drivers/bluetooth/hci_ldisc.c.(CVE-2019-15917)

  - An issue was discovered in the Linux kernel before
    4.20.15. The nfc_llcp_build_tlv function in
    net/nfc/llcp_commands.c may return NULL. If the caller
    does not check for this, it will trigger a NULL pointer
    dereference. This will cause denial of service. This
    affects nfc_llcp_build_gb in
    net/nfc/llcp_core.c.(CVE-2019-12818)

  - There is heap-based buffer overflow in kernel, all
    versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to
    cause a denial of service(system crash) or possibly
    execute arbitrary code.(CVE-2019-14816)

  - drivers/media/usb/dvb-usb/technisat-usb2.c in the Linux
    kernel through 5.2.9 has an out-of-bounds read via
    crafted USB device traffic (which may be remote via
    usbip or usbredir).(CVE-2019-15505)

  - There is heap-based buffer overflow in Linux kernel,
    all versions up to, excluding 5.3, in the marvell wifi
    chip driver in Linux kernel, that allows local users to
    cause a denial of service(system crash) or possibly
    execute arbitrary code.(CVE-2019-14814)

  - In the Linux kernel through 5.3.2,
    cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c
    does not reject a long SSID IE, leading to a Buffer
    Overflow.(CVE-2019-17133)

  - An issue was discovered in the Linux kernel before
    5.2.3. Out of bounds access exists in the functions
    ath6kl_wmi_pstream_timeout_event_rx and
    ath6kl_wmi_cac_event_rx in the file
    drivers/net/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)

  - In the Linux kernel 5.4.0-rc2, there is a
    use-after-free (read) in the __blk_add_trace function
    in kernel/trace/blktrace.c (which is used to fill out a
    blk_io_trace structure and place it in a per-cpu
    sub-buffer).(CVE-2019-19768)

  - An issue was discovered in the Linux kernel through
    5.5.6. set_fdc in drivers/block/floppy.c leads to a
    wait_til_ready out-of-bounds read because the FDC index
    is not checked for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)

  - An issue was discovered in the Linux kernel before
    5.0.9. There is a use-after-free in atalk_proc_exit,
    related to net/appletalk/atalk_proc.c,
    net/appletalk/ddp.c, and
    net/appletalk/sysctl_net_atalk.c.(CVE-2019-15292)

  - A heap-based buffer overflow was discovered in the
    Linux kernel, all versions 3.x.x and 4.x.x before
    4.18.0, in Marvell WiFi chip driver. The flaw could
    occur when the station attempts a connection
    negotiation during the handling of the remote devices
    country settings. This could allow the remote device to
    cause a denial of service (system crash) or possibly
    execute arbitrary code.(CVE-2019-14895)

  - In the Linux kernel, a certain net/ipv4/tcp_output.c
    change, which was properly incorporated into 4.16.12,
    was incorrectly backported to the earlier longterm
    kernels, introducing a new vulnerability that was
    potentially more severe than the issue that was
    intended to be fixed by backporting. Specifically, by
    adding to a write queue between disconnection and
    re-connection, a local attacker can trigger multiple
    use-after-free conditions. This can result in a kernel
    crash, or potentially in privilege
    escalation.(CVE-2019-15239)

  - The Linux kernel 4.x (starting from 4.1) and 5.x before
    5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass.
    Specifically, it is possible to extract the KASLR
    kernel image offset using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a
    static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is
    exposed. This attack can be carried out remotely, by
    the attacker forcing the target device to send UDP or
    ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is
    trivial if the server is a DNS server. ICMP traffic is
    trivial if the server answers ICMP Echo requests
    (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used
    to force UDP traffic to attacker-controlled IP
    addresses. NOTE: this attack against KASLR became
    viable in 4.1 because IP ID generation was changed to
    have a dependency on an address associated with a
    network namespace.(CVE-2019-10639)

  - The coredump implementation in the Linux kernel before
    5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs,
    which allows local users to obtain sensitive
    information, cause a denial of service, or possibly
    have unspecified other impact by triggering a race
    condition with mmget_not_zero or get_task_mm calls.
    This is related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and
    drivers/infiniband/core/uverbs_main.c.(CVE-2019-11599)

  - A memory leak in the adis_update_scan_mode() function
    in drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-ab612b1daf41.(CVE-2019-19060)

  - An issue was discovered in the Linux kernel before
    4.20.2. An out-of-bounds access exists in the function
    build_audio_procunit in the file
    sound/usb/mixer.c.(CVE-2019-15927)

  - An issue was discovered in net/wireless/nl80211.c in
    the Linux kernel through 5.2.17. It does not check the
    length of variable elements in a beacon head, leading
    to a buffer overflow.(CVE-2019-16746)

  - The Siemens R3964 line discipline driver in
    drivers/tty/n_r3964.c in the Linux kernel before 5.0.8
    has multiple race conditions.(CVE-2019-11486)

  - Insufficient access control in the Intel(R)
    PROSet/Wireless WiFi Software driver before version
    21.10 may allow an unauthenticated user to potentially
    enable denial of service via adjacent
    access.(CVE-2019-0136)

  - The Linux kernel through 5.3.13 has a start_offset+size
    Integer Overflow in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has
    its own mmap implementation. This allows local users
    (with /dev/video0 access) to obtain read and write
    permissions on kernel physical pages, which can
    possibly result in a privilege
    escalation(CVE-2019-18675)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2019-14815)

  - The Bluetooth BR/EDR specification up to and including
    version 5.1 permits sufficiently low encryption key
    length and does not prevent an attacker from
    influencing the key length negotiation. This allows
    practical brute-force attacks (aka 'KNOB') that can
    decrypt traffic and inject arbitrary ciphertext without
    the victim noticing.(CVE-2019-9506)

  - A memory leak in the ath9k_wmi_cmd() function in
    drivers/net/wireless/ath/ath9k/wmi.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption), aka
    CID-728c1e2a05e4.(CVE-2019-19074)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60a1ca93");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_81",
        "kernel-devel-3.10.0-862.14.1.6_81",
        "kernel-headers-3.10.0-862.14.1.6_81",
        "kernel-tools-3.10.0-862.14.1.6_81",
        "kernel-tools-libs-3.10.0-862.14.1.6_81"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
