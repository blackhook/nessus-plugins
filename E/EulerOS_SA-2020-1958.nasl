#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140328);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2019-19377",
    "CVE-2019-19462",
    "CVE-2019-20806",
    "CVE-2019-20810",
    "CVE-2019-20811",
    "CVE-2019-20812",
    "CVE-2019-9445",
    "CVE-2020-0009",
    "CVE-2020-0305",
    "CVE-2020-0543",
    "CVE-2020-10711",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10757",
    "CVE-2020-10766",
    "CVE-2020-10767",
    "CVE-2020-10768",
    "CVE-2020-10769",
    "CVE-2020-10781",
    "CVE-2020-10942",
    "CVE-2020-12114",
    "CVE-2020-12464",
    "CVE-2020-12465",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-12771",
    "CVE-2020-12826",
    "CVE-2020-12888",
    "CVE-2020-13143",
    "CVE-2020-13974",
    "CVE-2020-14331",
    "CVE-2020-14356",
    "CVE-2020-14416",
    "CVE-2020-15393",
    "CVE-2020-16166",
    "CVE-2020-25211",
    "CVE-2020-25220",
    "CVE-2020-25221"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2020-1958)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc. Security Fix(es):In the Android kernel in
    F2FS driver there is a possible out of bounds read due
    to a missing bounds check. This could lead to local
    information disclosure with system execution privileges
    needed. User interaction is not needed for
    exploitation.(CVE-2019-9445)In calc_vm_may_flags of
    ashmem.c, there is a possible arbitrary write to shared
    memory due to a permissions bypass. This could lead to
    local escalation of privilege by corrupting memory
    shared between processes, with no additional execution
    privileges needed. User interaction is not needed for
    exploitation. Product: Android Versions: Android kernel
    Android ID: A-142938932(CVE-2020-0009)A new domain
    bypass transient execution attack known as Special
    Register Buffer Data Sampling (SRBDS) has been found.
    This flaw allows data values from special internal
    registers to be leaked by an attacker able to execute
    code on any core of the CPU. An unprivileged, local
    attacker can use this flaw to infer values returned by
    affected instructions known to be commonly used during
    cryptographic operations that rely on uniqueness,
    secrecy, or both.(CVE-2020-0543)A flaw was found in the
    Linux kernel's implementation of the BTRFS file system.
    A local attacker, with the ability to mount a file
    system, can create a use-after-free memory fault after
    the file system has been unmounted. This may lead to
    memory corruption or privilege
    escalation.(CVE-2019-19377)A NULL pointer dereference
    flaw may occur in the Linux kernel's relay_open in
    kernel/relay.c. if the alloc_percpu() function is not
    validated in time of failure and used as a valid
    address for access. An attacker could use this flaw to
    cause a denial of service.(CVE-2019-19462)A NULL
    pointer dereference flaw was found in
    tw5864_handle_frame function in
    drivers/media/pci/tw5864/tw5864-video.c in the TW5864
    Series Video media driver. The pointer 'vb' is
    assigned, but not validated before its use, and can
    lead to a denial of service. This flaw allows a local
    attacker with special user or root privileges to crash
    the system or leak internal kernel
    information.(CVE-2019-20806)go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c in the Linux
    kernel before 5.6 does not call snd_card_free for a
    failure path, which causes a memory leak, aka
    CID-9453264ef586.(CVE-2019-20810)An issue was
    discovered in the Linux kernel before 5.0.6. In
    rx_queue_add_kobject() and netdev_queue_add_kobject()
    in net/coreet-sysfs.c, a reference count is mishandled,
    aka CID-a3e23f719f5c.(CVE-2019-20811)A flaw was found
    in the way the af_packet functionality in the Linux
    kernel handled the retirement timer setting for
    TPACKET_v3 when getting settings from the underlying
    network device errors out. This flaw allows a local
    user who can open the af_packet domain socket and who
    can hit the error path, to use this vulnerability to
    starve the system.(CVE-2019-20812)A NULL pointer
    dereference flaw was found in the Linux kernel's
    SELinux subsystem. This flaw occurs while importing the
    Commercial IP Security Option (CIPSO) protocol's
    category bitmap into the SELinux extensible bitmap via
    the' ebitmap_netlbl_import' routine. While processing
    the CIPSO restricted bitmap tag in the
    'cipso_v4_parsetag_rbm' routine, it sets the security
    attribute to indicate that the category bitmap is
    present, even if it has not been allocated. This issue
    leads to a NULL pointer dereference issue while
    importing the same category bitmap into SELinux. This
    flaw allows a remote network user to crash the system
    kernel, resulting in a denial of
    service.(CVE-2020-10711)A flaw was found in the Linux
    kernel's SELinux LSM hook implementation, where it
    anticipated the skb would only contain a single Netlink
    message. The hook incorrectly validated the first
    Netlink message in the skb only, to allow or deny the
    rest of the messages within the skb with the granted
    permissions and without further processing. At this
    time, there is no known ability for an attacker to
    abuse this flaw.(CVE-2020-10751)A flaw was found in the
    Linux Kernel in versions after 4.5-rc1 in the way
    mremap handled DAX Huge Pages. This flaw allows a local
    attacker with access to a DAX enabled storage to
    escalate their privileges on the
    system.(CVE-2020-10757)A logic bug flaw was found in
    the Linux kernel's implementation of SSBD. A bug in the
    logic handling allows an attacker with a local account
    to disable SSBD protection during a context switch when
    additional speculative execution mitigations are in
    place. This issue was introduced when the per
    task/process conditional STIPB switching was added on
    top of the existing SSBD switching. The highest threat
    from this vulnerability is to
    confidentiality.(CVE-2020-10766)A flaw was found in the
    Linux kernel's implementation of the Enhanced IBPB
    (Indirect Branch Prediction Barrier). The IBPB
    mitigation will be disabled when STIBP is not available
    or when the Enhanced Indirect Branch Restricted
    Speculation (IBRS) is available. This flaw allows a
    local attacker to perform a Spectre V2 style attack
    when this configuration is active. The highest threat
    from this vulnerability is to
    confidentiality.(CVE-2020-10767)A flaw was found in the
    prctl() function, where it can be used to enable
    indirect branch speculation after it has been disabled.
    This call incorrectly reports it as being 'force
    disabled' when it is not and opens the system to
    Spectre v2 attacks. The highest threat from this
    vulnerability is to confidentiality.(CVE-2020-10768)A
    flaw was found in the ZRAM kernel module, where a user
    with a local account and the ability to read the
    /sys/class/zram-control/hot_add file can create ZRAM
    device nodes in the /dev/ directory. This read
    allocates kernel memory and is not accounted for a user
    that triggers the creation of that ZRAM device. With
    this vulnerability, continually reading the device may
    consume a large amount of system memory and cause the
    Out-of-Memory (OOM) killer to activate and terminate
    random userspace processes, possibly making the system
    inoperable.(CVE-2020-10781)A stack buffer overflow
    issue was found in the get_raw_socket() routine of the
    Host kernel accelerator for virtio net (vhost-net)
    driver. It could occur while doing an
    ictol(VHOST_NET_SET_BACKEND) call, and retrieving
    socket name in a kernel stack variable via
    get_raw_socket(). A user able to perform ioctl(2) calls
    on the '/dev/vhost-net' device may use this flaw to
    crash the kernel resulting in DoS
    issue.(CVE-2020-10942)A flaw was found in the Linux
    kernel's implementation of the pivot_root syscall. This
    flaw allows a local privileged user (root outside or
    root inside a privileged container) to exploit a race
    condition to manipulate the reference count of the root
    filesystem. To be able to abuse this flaw, the process
    or user calling pivot_root must have advanced
    permissions. The highest threat from this vulnerability
    is to system availability.(CVE-2020-12114)A
    use-after-free flaw was found in usb_sg_cancel in
    drivers/usb/core/message.c in the USB core subsystem.
    This flaw allows a local attacker with a special user
    or root privileges to crash the system due to a race
    problem in the scatter-gather cancellation and transfer
    completion in usb_sg_wait. This vulnerability can also
    lead to a leak of internal kernel
    information.(CVE-2020-12464)A memory overflow and data
    corruption flaw were found in the Mediatek MT76 driver
    module for WiFi in mt76_add_fragment in
    driverset/wireless/mediatek/mt76/dma.c. An oversized
    packet with too many rx fragments causes an overflow
    and corruption in memory of adjacent pages. A local
    attacker with a special user or root privileges can
    cause a denial of service or a leak of internal kernel
    information.(CVE-2020-12465)A vulnerability was found
    in __mptctl_ioctl in drivers/message/fusion/mptctl.c in
    Fusion MPT base driver 'mptctl' in the SCSI device
    module, where an incorrect lock leads to a race
    problem. This flaw allows an attacker with local access
    and special user (or root) privileges to cause a denial
    of service.(CVE-2020-12652)A flaw was found in the way
    the mwifiex_cmd_append_vsie_tlv() in Linux kernel's
    Marvell WiFi-Ex driver handled vendor specific
    information elements. A local user could use this flaw
    to escalate their privileges on the
    system.(CVE-2020-12653)A flaw was found in the Linux
    kernel. The Marvell mwifiex driver allows a remote WiFi
    access point to trigger a heap-based memory buffer
    overflow due to an incorrect memcpy operation. The
    highest threat from this vulnerability is to data
    integrity and system availability.(CVE-2020-12654)A
    flaw was discovered in the XFS source in the Linux
    kernel. This flaw allows an attacker with the ability
    to mount an XFS filesystem, to trigger a denial of
    service while attempting to sync a file located on an
    XFS v5 image with crafted metadata.(CVE-2020-12655)An
    out-of-bounds (OOB) memory access flaw was found in the
    Network XDP (the eXpress Data Path) module in the Linux
    kernel's xdp_umem_reg function in net/xdp/xdp_umem.c.
    When a user with special user privilege of
    CAP_NET_ADMIN (or root) calls setsockopt to register
    umem ring on XDP socket, passing the headroom value
    larger than the available space in the chunk, it leads
    to an out-of-bounds write, causing panic or possible
    memory corruption. This flaw may lead to privilege
    escalation if a local end-user is granted permission to
    influence the execution of code in this
    manner.(CVE-2020-12659)A vulnerability was found in
    sg_write in drivers/scsi/sg.c in the SCSI generic (sg)
    driver subsystem. This flaw allows an attacker with
    local access and special user or root privileges to
    cause a denial of service if the allocated list is not
    cleaned with an invalid (Sg_fd * sfp) pointer at the
    time of failure, also possibly causing a kernel
    internal information leak problem.(CVE-2020-12770)An
    issue was discovered in the Linux kernel through
    5.6.11. btree_gc_coalesce in drivers/md/bcache/btree.c
    has a deadlock if a coalescing operation
    fails.(CVE-2020-12771)A flaw was found in the Linux
    kernel loose validation of child/parent process
    identification handling while filtering signal
    handlers. A local attacker is able to abuse this flaw
    to bypass checks to send any signal to a privileged
    process.(CVE-2020-12826)A flaw was found in the Linux
    kernel, where it allows userspace processes, for
    example, a guest VM, to directly access h/w devices via
    its VFIO driver modules. The VFIO modules allow users
    to enable or disable access to the devices' MMIO memory
    address spaces. If a user attempts to access the
    read/write devices' MMIO address space when it is
    disabled, some h/w devices issue an interrupt to the
    CPU to indicate a fatal error condition, crashing the
    system. This flaw allows a guest user or process to
    crash the host system resulting in a denial of
    service.(CVE-2020-12888)gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)** DISPUTED ** An
    issue was discovered in the Linux kernel through 5.7.1.
    drivers/tty/vt/keyboard.c has an integer overflow if
    k_ascii is called several times in a row, aka
    CID-b86dab054059. NOTE: Members in the community argue
    that the integer overflow does not lead to a security
    issue in this case.(CVE-2020-13974)A use-after-free
    flaw was found in slcan_write_wakeup in
    driverset/can/slcan.c in the serial CAN module slcan. A
    race condition occurs when communicating with can using
    slcan between the write (scheduling the transmit) and
    closing (flushing out any pending queues) the SLCAN
    channel. This flaw allows a local attacker with special
    user or root privileges to cause a denial of service or
    a kernel information leak. The highest threat from this
    vulnerability is to system
    availability.(CVE-2020-14416)In the Linux kernel
    through 5.7.6, usbtest_disconnect in
    drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770.(CVE-2020-15393)The Linux kernel
    through 5.7.11 allows remote attackers to make
    observations that help to obtain sensitive information
    about the internal state of the network RNG, aka
    CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and
    kernel/time/timer.c.(CVE-2020-16166)A flaw was found in
    the Linux kernel's implementation of Userspace core
    dumps. This flaw allows an attacker with a local
    account to crash a trivial program and exfiltrate
    private kernel data.(CVE-2020-10732)A flaw null pointer
    dereference in the Linux kernel cgroupv2 subsystem in
    versions before 5.7.10 was found in the way when reboot
    the system. A local user could use this flaw to crash
    the system or escalate their privileges on the
    system.(CVE-2020-14356)The Linux kernel 4.9.x before
    4.9.233, 4.14.x before 4.14.194, and 4.19.x before
    4.19.140 has a use-after-free because skcd->no_refcnt
    was not considered during a backport of a
    CVE-2020-14356 patch. This is related to the cgroups
    feature.(CVE-2020-25220)get_gate_page in mm/gup.c in
    the Linux kernel 5.7.x and 5.8.x before 5.8.7 allows
    privilege escalation because of incorrect reference
    counting (caused by gate page mishandling) of the
    struct page that backs the vsyscall page. The result is
    a refcount underflow. This can be triggered by any
    64-bit process that can use ptrace() or
    process_vm_readv(), aka
    CID-9fa2dd946743.(CVE-2020-25221)In the Linux kernel
    through 5.8.7, local attackers able to inject conntrack
    netlink configuration could overflow a local buffer,
    causing crashes or triggering use of incorrect protocol
    numbers in ctnetlink_parse_tuple_filter in
    net/netfilter/nf_conntrack_netlink.c, aka
    CID-1cc5ef91d2ff.(CVE-2020-25211)A buffer over-read
    flaw was found in RH kernel versions before 5.0 in
    crypto_authenc_extractkeys in crypto/authenc.c in the
    IPsec Cryptographic algorithm's module, authenc. When a
    payload longer than 4 bytes, and is not following
    4-byte alignment boundary guidelines, it causes a
    buffer over-read threat, leading to a system crash.
    This flaw allows a local attacker with user privileges
    to cause a denial of service.(CVE-2020-10769)A flaw was
    found in the Linux kernel's implementation of the
    invert video code on VGA consoles when a local attacker
    attempts to resize the console, calling an ioctl
    VT_RESIZE, which causes an out-of-bounds write to
    occur. This flaw allows a local user with access to the
    VGA console to crash the system, potentially escalating
    their privileges on the system. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-14331)In cdev_get of char_dev.c,
    there is a possible use-after-free due to a race
    condition. This could lead to local escalation of
    privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android-10Android ID:
    A-153467744(CVE-2020-0305)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea61decf");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13974");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

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

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h820",
        "kernel-devel-4.19.36-vhulk1907.1.0.h820",
        "kernel-headers-4.19.36-vhulk1907.1.0.h820",
        "kernel-tools-4.19.36-vhulk1907.1.0.h820",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h820",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h820",
        "perf-4.19.36-vhulk1907.1.0.h820",
        "python-perf-4.19.36-vhulk1907.1.0.h820"];

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
