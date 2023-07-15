#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130736);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-5754",
    "CVE-2017-5897",
    "CVE-2017-7261",
    "CVE-2017-7472",
    "CVE-2017-7518",
    "CVE-2018-10124",
    "CVE-2018-10323",
    "CVE-2018-1066",
    "CVE-2018-10675",
    "CVE-2018-13094",
    "CVE-2018-20976",
    "CVE-2018-3693",
    "CVE-2018-6412",
    "CVE-2018-7995",
    "CVE-2018-9363",
    "CVE-2018-9518",
    "CVE-2019-10140",
    "CVE-2019-10142",
    "CVE-2019-10207",
    "CVE-2019-1125",
    "CVE-2019-12378",
    "CVE-2019-12381",
    "CVE-2019-12382",
    "CVE-2019-12456",
    "CVE-2019-12818",
    "CVE-2019-13631",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-14284",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-15098",
    "CVE-2019-15118",
    "CVE-2019-15212",
    "CVE-2019-15213",
    "CVE-2019-15214",
    "CVE-2019-15215",
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15218",
    "CVE-2019-15219",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15239",
    "CVE-2019-15292",
    "CVE-2019-15505",
    "CVE-2019-15807",
    "CVE-2019-15916",
    "CVE-2019-15926",
    "CVE-2019-15927",
    "CVE-2019-16413",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17056",
    "CVE-2019-2101",
    "CVE-2019-3846",
    "CVE-2019-3882",
    "CVE-2019-9500",
    "CVE-2019-9503",
    "CVE-2019-9506"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-2274)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):Systems with
    microprocessors utilizing speculative execution and
    indirect branch prediction may allow unauthorized
    disclosure of information to an attacker with local
    user access via a side-channel analysis of the data
    cache.(CVE-2017-5754)The ip6gre_err function in
    net/ipv6/ip6_gre.c in the Linux kernel allows remote
    attackers to have unspecified impact via vectors
    involving GRE flags in an IPv6 packet, which trigger an
    out-of-bounds access.(CVE-2017-5897)The
    vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel through 4.10.5 does not check for a zero value
    of certain levels data, which allows local users to
    cause a denial of service (ZERO_SIZE_PTR dereference,
    and GPF and possibly panic) via a crafted ioctl call
    for a /dev/dri/renderD* device.(CVE-2017-7261)The KEYS
    subsystem in the Linux kernel before 4.10.13 allows
    local users to cause a denial of service (memory
    consumption) via a series of
    KEY_REQKEY_DEFL_THREAD_KEYRING
    keyctl_set_reqkey_keyring calls.(CVE-2017-7472)A flaw
    was found in the Linux kernel before version 4.12 in
    the way the KVM module processed the trap flag(TF) bit
    in EFLAGS during emulation of the syscall instruction,
    which leads to a debug exception(#DB) being raised in
    the guest stack. A user/process inside a guest could
    use this flaw to potentially escalate their privileges
    inside the guest. Linux guests are not affected by
    this.(CVE-2017-7518)The kill_something_info function in
    kernel/signal.c in the Linux kernel before 4.13, when
    an unspecified architecture and compiler is used, might
    allow local users to cause a denial of service via an
    INT_MIN argument.(CVE-2018-10124)The
    xfs_bmap_extents_to_btree function in
    fs/xfs/libxfs/xfs_bmap.c in the Linux kernel through
    4.16.3 allows local users to cause a denial of service
    (xfs_bmapi_write NULL pointer dereference) via a
    crafted xfs image.(CVE-2018-10323)The Linux kernel
    before version 4.11 is vulnerable to a NULL pointer
    dereference in fs/cifs/cifsencrypt.c:setup_ntlmv2_rsp()
    that allows an attacker controlling a CIFS server to
    kernel panic a client that has this server mounted,
    because an empty TargetInfo field in an NTLMSSP setup
    negotiation response is mishandled during session
    recovery.(CVE-2018-1066)The do_get_mempolicy function
    in mm/mempolicy.c in the Linux kernel before 4.12.9
    allows local users to cause a denial of service
    (use-after-free) or possibly have unspecified other
    impact via crafted system calls.(CVE-2018-10675)An
    issue was discovered in fs/xfs/libxfs/xfs_attr_leaf.c
    in the Linux kernel through 4.17.3. An OOPS may occur
    for a corrupted xfs image after xfs_da_shrink_inode()
    is called with a NULL bp.(CVE-2018-13094)An issue was
    discovered in fs/xfs/xfs_super.c in the Linux kernel
    before 4.18. A use after free exists, related to
    xfs_fs_fill_super failure.(CVE-2018-20976)Systems with
    microprocessors utilizing speculative execution and
    branch prediction may allow unauthorized disclosure of
    information to an attacker with local user access via a
    speculative buffer overflow and side-channel
    analysis.(CVE-2018-3693)In the function
    sbusfb_ioctl_helper() in drivers/video/fbdev/sbuslib.c
    in the Linux kernel through 4.15, an integer signedness
    error allows arbitrary information leakage for the
    FBIOPUTCMAP_SPARC and FBIOGETCMAP_SPARC
    commands.(CVE-2018-6412)Race condition in the
    store_int_with_restart() function in
    arch/x86/kernel/cpu/mcheck/mce.c in the Linux kernel
    through 4.15.7 allows local users to cause a denial of
    service (panic) by leveraging root access to write to
    the check_interval file in a
    /sys/devices/system/machinecheck/machinecheck
    directory. NOTE: a third party has indicated that this
    report is not security relevant.(CVE-2018-7995)In the
    hidp_process_report in bluetooth, there is an integer
    overflow. This could lead to an out of bounds write
    with no additional execution privileges needed. User
    interaction is not needed for exploitation. Product:
    Android Versions: Android kernel Android ID: A-65853588
    References: Upstream kernel.(CVE-2018-9363)In
    nfc_llcp_build_sdreq_tlv of llcp_commands.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with System execution privileges needed. User
    interaction is not needed for exploitation. Product:
    Android. Versions: Android kernel. Android ID:
    A-73083945.(CVE-2018-9518)A vulnerability was found in
    Linux kernel's, versions up to 3.10, implementation of
    overlayfs. An attacker with local access can create a
    denial of service situation via NULL pointer
    dereference in ovl_posix_acl_create function in
    fs/overlayfs/dir.c. This can allow attackers with
    ability to create directories on overlayfs to crash the
    kernel creating a denial of service
    (DOS).(CVE-2019-10140)A flaw was found in the Linux
    kernel's freescale hypervisor manager implementation,
    kernel versions 5.0.x up to, excluding 5.0.17. A
    parameter passed to an ioctl was incorrectly validated
    and used in size calculations for the page size
    calculation. An attacker can use this flaw to crash the
    system, corrupt memory, or create other adverse
    security affects.(CVE-2019-10142)A flaw was found in
    the Linux kernel's Bluetooth implementation of UART. An
    attacker with local access and write permissions to the
    Bluetooth hardware could use this flaw to issue a
    specially crafted ioctl function call and cause the
    system to crash.(CVE-2019-10207)An information
    disclosure vulnerability exists when certain central
    processing units (CPU) speculatively access memory, aka
    'Windows Kernel Information Disclosure Vulnerability'.
    This CVE ID is unique from CVE-2019-1071,
    CVE-2019-1073.(CVE-2019-1125)An issue was discovered in
    ip6_ra_control in net/ipv6/ipv6_sockglue.c in the Linux
    kernel through 5.1.5. There is an unchecked kmalloc of
    new_ra, which might allow an attacker to cause a denial
    of service (NULL pointer dereference and system crash).
    NOTE: This has been disputed as not an
    issue.(CVE-2019-12378)An issue was discovered in
    ip_ra_control in net/ipv4/ip_sockglue.c in the Linux
    kernel through 5.1.5. There is an unchecked kmalloc of
    new_ra, which might allow an attacker to cause a denial
    of service (NULL pointer dereference and system crash).
    NOTE: this is disputed because new_ra is never used if
    it is NULL.(CVE-2019-12381)An issue was discovered in
    drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c in the Linux kernel
    through 5.1.5. There is an unchecked kstrdup of fwstr,
    which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash).
    NOTE: The vendor disputes this issues as not being a
    vulnerability because kstrdup() returning NULL is
    handled sufficiently and there is no chance for a NULL
    pointer dereference.(CVE-2019-12382)An issue was
    discovered in the MPT3COMMAND case in _ctl_ioctl_main
    in drivers/scsi/mpt3sas/mpt3sas_ctl.c in the Linux
    kernel through 5.1.5. It allows local users to cause a
    denial of service or possibly have unspecified other
    impact by changing the value of ioc_number between two
    kernel reads of that value, aka a double fetch
    vulnerability. NOTE: a third party reports that this is
    unexploitable because the doubly fetched value is not
    used.(CVE-2019-12456)An issue was discovered in the
    Linux kernel before 4.20.15. The nfc_llcp_build_tlv
    function in net fc/llcp_commands.c may return NULL. If
    the caller does not check for this, it will trigger a
    NULL pointer dereference. This will cause denial of
    service. This affects nfc_llcp_build_gb in
    netfc/llcp_core.c.(CVE-2019-12818)In
    parse_hid_report_descriptor in
    drivers/input/tablet/gtco.c in the Linux kernel through
    5.2.1, a malicious USB device can send an HID report
    that triggers an out-of-bounds write during generation
    of debugging messages.(CVE-2019-13631)In the Linux
    kernel through 5.2.1 on the powerpc platform, when
    hardware transactional memory is disabled, a local user
    can cause a denial of service (TM Bad Thing exception
    and system crash) via a sigreturn() system call that
    sends a crafted signal frame. This affects
    arch/powerpc/kernel/signal_32.c and
    arch/powerpc/kernel/signal_64.c.(CVE-2019-13648)In the
    Linux kernel before 5.2.3, set_geometry in
    drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and
    out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been
    inserted. NOTE: QEMU creates the floppy device by
    default.(CVE-2019-14283)In the Linux kernel before
    5.2.3, drivers/block/floppy.c allows a denial of
    service by setup_format_params division-by-zero. Two
    consecutive ioctls can trigger the bug: the first one
    should set the drive geometry with .sect and .rate
    values that make F_SECT_PER_TRACK be zero. Next, the
    floppy format operation should be called. It can be
    triggered by an unprivileged local user even when a
    floppy disk has not been inserted. NOTE: QEMU creates
    the floppy device by default.(CVE-2019-14284)There is
    heap-based buffer overflow in Linux kernel, all
    versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to
    cause a denial of service(system crash) or possibly
    execute arbitrary code.(CVE-2019-14814)There is
    heap-based buffer overflow in marvell wifi chip driver
    in Linux kernel,allows local users to cause a denial of
    service(system crash) or possibly execute arbitrary
    code.(CVE-2019-14815)There is heap-based buffer
    overflow in kernel, all versions up to, excluding 5.3,
    in the marvell wifi chip driver in Linux kernel, that
    allows local users to cause a denial of service(system
    crash) or possibly execute arbitrary
    code.(CVE-2019-14816)An out-of-bounds access issue was
    found in the Linux kernel, all versions through 5.3, in
    the way Linux kernel's KVM hypervisor implements the
    Coalesced MMIO write operation. It operates on an MMIO
    ring buffer 'struct kvm_coalesced_mmio' object, wherein
    write indices 'ring->first' and 'ring->last' value
    could be supplied by a host user-space process. An
    unprivileged host user or process with access to
    '/dev/kvm' device could use this flaw to crash the host
    kernel, resulting in a denial of service or potentially
    escalating privileges on the system.(CVE-2019-14821)A
    buffer overflow flaw was found, in versions from 2.6.34
    to 5.2.x, in the way Linux kernel's vhost functionality
    that translates virtqueue buffers to IOVs, logged the
    buffer descriptors during migration. A privileged guest
    user able to pass descriptors with invalid length to
    the host when migration is underway, could use this
    flaw to increase their privileges on the
    host.(CVE-2019-14835)drivers
    et/wireless/ath/ath6kl/usb.c in the Linux kernel
    through 5.2.9 has a NULL pointer dereference via an
    incomplete address in an endpoint
    descriptor.(CVE-2019-15098)check_input_term in
    sound/usb/mixer.c in the Linux kernel through 5.2.9
    mishandles recursion, leading to kernel stack
    exhaustion.(CVE-2019-15118)An issue was discovered in
    the Linux kernel before 5.1.8. There is a double-free
    caused by a malicious USB device in the
    drivers/usb/misc/rio500.c driver.(CVE-2019-15212)An
    issue was discovered in the Linux kernel before 5.2.3.
    There is a use-after-free caused by a malicious USB
    device in the drivers/media/usb/dvb-usb/dvb-usb-init.c
    driver.(CVE-2019-15213)An issue was discovered in the
    Linux kernel before 5.0.10. There is a use-after-free
    in the sound subsystem because card disconnection
    causes certain data structures to be deleted too early.
    This is related to sound/core/init.c and
    sound/core/info.c.(CVE-2019-15214)An issue was
    discovered in the Linux kernel before 5.2.6. There is a
    use-after-free caused by a malicious USB device in the
    drivers/media/usb/cpia2/cpia2_usb.c
    driver.(CVE-2019-15215)An issue was discovered in the
    Linux kernel before 5.0.14. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver.(CVE-2019-15216)An
    issue was discovered in the Linux kernel before 5.2.3.
    There is a NULL pointer dereference caused by a
    malicious USB device in the
    drivers/media/usb/zr364xx/zr364xx.c
    driver.(CVE-2019-15217)An issue was discovered in the
    Linux kernel before 5.1.8. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/media/usb/siano/smsusb.c
    driver.(CVE-2019-15218)An issue was discovered in the
    Linux kernel before 5.1.8. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/usb/misc/sisusbvga/sisusb.c
    driver.(CVE-2019-15219)An issue was discovered in the
    Linux kernel before 5.2.1. There is a use-after-free
    caused by a malicious USB device in the drivers
    et/wireless/intersil/p54/p54usb.c
    driver.(CVE-2019-15220)An issue was discovered in the
    Linux kernel before 5.1.17. There is a NULL pointer
    dereference caused by a malicious USB device in the
    sound/usb/line6/pcm.c driver.(CVE-2019-15221)In the
    Linux kernel, a certain net/ipv4/tcp_output.c change,
    which was properly incorporated into 4.16.12, was
    incorrectly backported to the earlier longterm kernels,
    introducing a new vulnerability that was potentially
    more severe than the issue that was intended to be
    fixed by backporting. Specifically, by adding to a
    write queue between disconnection and re-connection, a
    local attacker can trigger multiple use-after-free
    conditions. This can result in a kernel crash, or
    potentially in privilege escalation. NOTE: this affects
    (for example) Linux distributions that use 4.9.x
    longterm kernels before 4.9.190 or 4.14.x longterm
    kernels before 4.14.139.(CVE-2019-15239)An issue was
    discovered in the Linux kernel before 5.0.9. There is a
    use-after-free in atalk_proc_exit, related to
    net/appletalk/atalk_proc.c, net/appletalk/ddp.c, and
    net/appletalk/sysctl_net_atalk.c.(CVE-2019-15292)driver
    s/media/usb/dvb-usb/technisat-usb2.c in the Linux
    kernel through 5.2.9 has an out-of-bounds read via
    crafted USB device traffic (which may be remote via
    usbip or usbredir).(CVE-2019-15505)In the Linux kernel
    before 5.1.13, there is a memory leak in
    drivers/scsi/libsas/sas_expander.c when SAS expander
    discovery fails. This will cause a BUG and denial of
    service.(CVE-2019-15807)An issue was discovered in the
    Linux kernel before 5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core et-sysfs.c, which
    will cause denial of service.(CVE-2019-15916)An issue
    was discovered in the Linux kernel before 5.2.3. Out of
    bounds access exists in the functions
    ath6kl_wmi_pstream_timeout_event_rx and
    ath6kl_wmi_cac_event_rx in the file
    driverset/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)An
    issue was discovered in the Linux kernel before 4.20.2.
    An out-of-bounds access exists in the function
    build_audio_procunit in the file
    sound/usb/mixer.c.(CVE-2019-15927)An issue was
    discovered in the Linux kernel before 5.0.4. The 9p
    filesystem did not protect i_size_write() properly,
    which causes an i_size_read() infinite loop and denial
    of service on SMP systems.(CVE-2019-16413)ax25_create
    in net/ax25/af_ax25.c in the AF_AX25 network module in
    the Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-0614e2b73768.(CVE-2019-17052)ieee802154_create in
    net/ieee802154/socket.c in the AF_IEEE802154 network
    module in the Linux kernel through 5.3.2 does not
    enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-e69dbd4619e7.(CVE-2019-17053)atalk_create in
    net/appletalk/ddp.c in the AF_APPLETALK network module
    in the Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-6cc03e8aa36c.(CVE-2019-17054)base_sock_create in
    drivers/isdn/mISDN/socket.c in the AF_ISDN network
    module in the Linux kernel through 5.3.2 does not
    enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-b91ee4aa2a21.(CVE-2019-17055)llcp_sock_create in
    net fc/llcp_sock.c in the AF_NFC network module in the
    Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-3a359798b176.(CVE-2019-17056)In
    uvc_parse_standard_control of uvc_driver.c, there is a
    possible out-of-bound read due to improper input
    validation. This could lead to local information
    disclosure with no additional execution privileges
    needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android
    kernel. Android ID: A-111760968.(CVE-2019-2101)A flaw
    that allowed an attacker to corrupt memory and possibly
    escalate privileges was found in the mwifiex kernel
    module while connecting to a malicious wireless
    network.(CVE-2019-3846)A flaw was found in the Linux
    kernel's vfio interface implementation that permits
    violation of the user's locked memory limit. If a
    device is bound to a vfio driver, such as vfio-pci, and
    the local attacker is administratively granted
    ownership of the device, it may cause a system memory
    exhaustion and thus a denial of service (DoS). Versions
    3.10, 4.14 and 4.18 are vulnerable.(CVE-2019-3882)If
    the Wake-up on Wireless LAN functionality is configured
    in the brcmfmac driver, which only works with Broadcom
    FullMAC chipsets, a malicious event frame can be
    constructed to trigger a heap buffer overflow in the
    brcmf_wowl_nd_results() function. This vulnerability
    can be exploited by compromised chipsets to compromise
    the host, or when used in combination with another
    brcmfmac driver flaw (CVE-2019-9503), can be used
    remotely. This can result in a remote denial of service
    (DoS). Due to the nature of the flaw, a remote
    privilege escalation cannot be fully ruled
    out.(CVE-2019-9500)If the brcmfmac driver receives a
    firmware event frame from a remote source, the
    is_wlc_event_frame function will cause this frame to be
    discarded and not be processed. If the driver receives
    the firmware event frame from the host, the appropriate
    handler is called. This frame validation can be
    bypassed if the bus used is USB (for instance by a WiFi
    dongle). This can allow firmware event frames from a
    remote source to be processed and this can result in
    denial of service (DoS) condition.(CVE-2019-9503)The
    Bluetooth BR/EDR specification up to and including
    version 5.1 permits sufficiently low encryption key
    length and does not prevent an attacker from
    influencing the key length negotiation. This allows
    practical brute-force attacks (aka KNOB) that can
    decrypt traffic and inject arbitrary ciphertext without
    the victim noticing.(CVE-2019-9506)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2274
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8e6c94c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h232",
        "kernel-debuginfo-3.10.0-514.44.5.10.h232",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h232",
        "kernel-devel-3.10.0-514.44.5.10.h232",
        "kernel-headers-3.10.0-514.44.5.10.h232",
        "kernel-tools-3.10.0-514.44.5.10.h232",
        "kernel-tools-libs-3.10.0-514.44.5.10.h232",
        "perf-3.10.0-514.44.5.10.h232",
        "python-perf-3.10.0-514.44.5.10.h232"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
