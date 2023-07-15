#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131845);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-1446",
    "CVE-2015-1350",
    "CVE-2015-3332",
    "CVE-2015-8816",
    "CVE-2015-9289",
    "CVE-2016-2184",
    "CVE-2016-2185",
    "CVE-2016-2186",
    "CVE-2016-2187",
    "CVE-2016-2384",
    "CVE-2016-2782",
    "CVE-2016-3138",
    "CVE-2016-3139",
    "CVE-2016-3140",
    "CVE-2016-3689",
    "CVE-2016-4569",
    "CVE-2016-4578",
    "CVE-2016-4580",
    "CVE-2016-7425",
    "CVE-2017-1000379",
    "CVE-2017-11089",
    "CVE-2017-13167",
    "CVE-2017-13216",
    "CVE-2017-13305",
    "CVE-2017-14051",
    "CVE-2017-18232",
    "CVE-2017-18509",
    "CVE-2017-18551",
    "CVE-2017-18595",
    "CVE-2017-7261",
    "CVE-2017-7472",
    "CVE-2018-10087",
    "CVE-2018-10124",
    "CVE-2018-10322",
    "CVE-2018-10323",
    "CVE-2018-10675",
    "CVE-2018-10880",
    "CVE-2018-12896",
    "CVE-2018-17972",
    "CVE-2018-18710",
    "CVE-2018-20511",
    "CVE-2018-20856",
    "CVE-2018-20976",
    "CVE-2018-3693",
    "CVE-2018-6412",
    "CVE-2018-9518",
    "CVE-2019-0136",
    "CVE-2019-10140",
    "CVE-2019-10142",
    "CVE-2019-1125",
    "CVE-2019-12378",
    "CVE-2019-12379",
    "CVE-2019-12381",
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
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15218",
    "CVE-2019-15219",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15291",
    "CVE-2019-15292",
    "CVE-2019-15505",
    "CVE-2019-15807",
    "CVE-2019-15916",
    "CVE-2019-15926",
    "CVE-2019-15927",
    "CVE-2019-16232",
    "CVE-2019-16413",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17056",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2019-2101",
    "CVE-2019-3846",
    "CVE-2019-3882",
    "CVE-2019-9503"
  );
  script_bugtraq_id(
    64954,
    74232
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2019-2353)");
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
    output, etc.Security Fix(es):The yam_ioctl function in
    drivers et/hamradio/yam.c in the Linux kernel before
    3.12.8 does not initialize a certain structure member,
    which allows local users to obtain sensitive
    information from kernel memory by leveraging the
    CAP_NET_ADMIN capability for an SIOCYAMGCFG ioctl
    call.(CVE-2014-1446)The VFS subsystem in the Linux
    kernel 3.x provides an incomplete set of requirements
    for setattr operations that underspecifies removing
    extended privilege attributes, which allows local users
    to cause a denial of service (capability stripping) via
    a failed invocation of a system call, as demonstrated
    by using chown to remove a capability from the ping or
    Wireshark dumpcap program.(CVE-2015-1350)A certain
    backport in the TCP Fast Open implementation for the
    Linux kernel before 3.18 does not properly maintain a
    count value, which allow local users to cause a denial
    of service (system crash) via the Fast Open feature, as
    demonstrated by visiting the
    chrome://flags/#enable-tcp-fast-open URL when using
    certain 3.10.x through 3.16.x kernel builds, including
    longterm-maintenance releases and ckt (aka Canonical
    Kernel Team) builds.(CVE-2015-3332)The hub_activate
    function in drivers/usb/core/hub.c in the Linux kernel
    before 4.3.5 does not properly maintain a hub-interface
    data structure, which allows physically proximate
    attackers to cause a denial of service (invalid memory
    access and system crash) or possibly have unspecified
    other impact by unplugging a USB hub
    device.(CVE-2015-8816)In the Linux kernel before 4.1.4,
    a buffer overflow occurs when checking userspace params
    in drivers/media/dvb-frontends/cx24116.c. The maximum
    size for a DiSEqC command is 6, according to the
    userspace API. However, the code allows larger values
    such as 23.(CVE-2015-9289)The create_fixed_stream_quirk
    function in sound/usb/quirks.c in the snd-usb-audio
    driver in the Linux kernel before 4.5.1 allows
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference or double free, and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2184)The ati_remote2_probe
    function in drivers/input/misc/ati_remote2.c in the
    Linux kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a crafted endpoints
    value in a USB device descriptor.(CVE-2016-2185)The
    powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2186)The gtco_probe
    function in drivers/input/tablet/gtco.c in the Linux
    kernel through 4.5.2 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a crafted endpoints
    value in a USB device descriptor.(CVE-2016-2187)Double
    free vulnerability in the snd_usbmidi_create function
    in sound/usb/midi.c in the Linux kernel before 4.5
    allows physically proximate attackers to cause a denial
    of service (panic) or possibly have unspecified other
    impact via vectors involving an invalid USB
    descriptor.(CVE-2016-2384)The treo_attach function in
    drivers/usb/serial/visor.c in the Linux kernel before
    4.5 allows physically proximate attackers to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact by
    inserting a USB device that lacks a (1) bulk-in or (2)
    interrupt-in endpoint.(CVE-2016-2782)The acm_probe
    function in drivers/usb/class/cdc-acm.c in the Linux
    kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a USB device without
    both a control and a data endpoint
    descriptor.(CVE-2016-3138)The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    before 3.17 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-3139)The digi_port_init
    function in drivers/usb/serial/digi_acceleport.c in the
    Linux kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a crafted endpoints
    value in a USB device descriptor.(CVE-2016-3140)The
    ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel before
    4.5.1 allows physically proximate attackers to cause a
    denial of service (system crash) via a USB device
    without both a master and a slave
    interface.(CVE-2016-3689)The snd_timer_user_params
    function in sound/core/timer.c in the Linux kernel
    through 4.6 does not initialize a certain data
    structure, which allows local users to obtain sensitive
    information from kernel stack memory via crafted use of
    the ALSA timer
    interface.(CVE-2016-4569)sound/core/timer.c in the
    Linux kernel through 4.6 does not initialize certain r1
    data structures, which allows local users to obtain
    sensitive information from kernel stack memory via
    crafted use of the ALSA timer interface, related to the
    (1) snd_timer_user_ccallback and (2)
    snd_timer_user_tinterrupt functions.(CVE-2016-4578)The
    x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel before
    4.5.5 does not properly initialize a certain data
    structure, which allows attackers to obtain sensitive
    information from kernel stack memory via an X.25 Call
    Request.(CVE-2016-4580)The arcmsr_iop_message_xfer
    function in drivers/scsi/arcmsr/arcmsr_hba.c in the
    Linux kernel through 4.8.2 does not restrict a certain
    length field, which allows local users to gain
    privileges or cause a denial of service (heap-based
    buffer overflow) via an ARCMSR_MESSAGE_WRITE_WQBUFFER
    control code.(CVE-2016-7425)The Linux Kernel running on
    AMD64 systems will sometimes map the contents of PIE
    executable, the heap or ld.so to where the stack is
    mapped allowing attackers to more easily manipulate the
    stack. Linux Kernel version 4.11.5 is
    affected.(CVE-2017-1000379)In android for MSM, Firefox
    OS for MSM, QRD Android, with all Android releases from
    CAF using the Linux kernel, a buffer overread is
    observed in nl80211_set_station when user space
    application sends attribute
    NL80211_ATTR_LOCAL_MESH_POWER_MODE with data of size
    less than 4 bytes(CVE-2017-11089)An elevation of
    privilege vulnerability in the kernel sound timer.
    Product: Android. Versions: Android kernel. Android ID
    A-37240993.(CVE-2017-13167)In ashmem_ioctl of ashmem.c,
    there is an out-of-bounds write due to insufficient
    locking when accessing asma. This could lead to a local
    elevation of privilege enabling code execution as a
    privileged process with no additional execution
    privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android
    kernel. Android ID: A-66954097.(CVE-2017-13216)A
    information disclosure vulnerability in the Upstream
    kernel encrypted-keys. Product: Android. Versions:
    Android kernel. Android ID:
    A-70526974.(CVE-2017-13305)An integer overflow in the
    qla2x00_sysfs_write_optrom_ctl function in
    drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel
    through 4.12.10 allows local users to cause a denial of
    service (memory corruption and system crash) by
    leveraging root access.(CVE-2017-14051)The Serial
    Attached SCSI (SAS) implementation in the Linux kernel
    through 4.15.9 mishandles a mutex within libsas, which
    allows local users to cause a denial of service
    (deadlock) by triggering certain error-handling
    code.(CVE-2017-18232)An issue was discovered in
    net/ipv6/ip6mr.c in the Linux kernel before 4.11. By
    setting a specific socket option, an attacker can
    control a pointer in kernel land and cause an
    inet_csk_listen_stop general protection fault, or
    potentially execute arbitrary code under certain
    circumstances. The issue can be triggered as root
    (e.g., inside a default LXC container or with the
    CAP_NET_ADMIN capability) or after namespace unsharing.
    This occurs because sk_type and protocol are not
    checked in the appropriate part of the ip6_mroute_*
    functions. NOTE: this affects Linux distributions that
    use 4.9.x longterm kernels before
    4.9.187.(CVE-2017-18509)An issue was discovered in
    drivers/i2c/i2c-core-smbus.c in the Linux kernel before
    4.14.15. There is an out of bounds write in the
    function i2c_smbus_xfer_emulated.(CVE-2017-18551)An
    issue was discovered in the Linux kernel before
    4.14.11. A double free may be caused by the function
    allocate_trace_buffer in the file
    kernel/trace/trace.c.(CVE-2017-18595)The
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
    keyctl_set_reqkey_keyring calls.(CVE-2017-7472)The
    kernel_wait4 function in kernel/exit.c in the Linux
    kernel before 4.13, when an unspecified architecture
    and compiler is used, might allow local users to cause
    a denial of service by triggering an attempted use of
    the -INT_MIN value.(CVE-2018-10087)The
    kill_something_info function in kernel/signal.c in the
    Linux kernel before 4.13, when an unspecified
    architecture and compiler is used, might allow local
    users to cause a denial of service via an INT_MIN
    argument.(CVE-2018-10124)The xfs_dinode_verify function
    in fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel
    through 4.16.3 allows local users to cause a denial of
    service (xfs_ilock_attr_map_shared invalid pointer
    dereference) via a crafted xfs
    image.(CVE-2018-10322)The xfs_bmap_extents_to_btree
    function in fs/xfs/libxfs/xfs_bmap.c in the Linux
    kernel through 4.16.3 allows local users to cause a
    denial of service (xfs_bmapi_write NULL pointer
    dereference) via a crafted xfs
    image.(CVE-2018-10323)The do_get_mempolicy function in
    mm/mempolicy.c in the Linux kernel before 4.12.9 allows
    local users to cause a denial of service
    (use-after-free) or possibly have unspecified other
    impact via crafted system calls.(CVE-2018-10675)Linux
    kernel is vulnerable to a stack-out-of-bounds write in
    the ext4 filesystem code when mounting and writing to a
    crafted ext4 image in ext4_update_inline_data(). An
    attacker could use this to cause a system crash and a
    denial of service.(CVE-2018-10880)An issue was
    discovered in the Linux kernel through 4.17.3. An
    Integer Overflow in kernel/time/posix-timers.c in the
    POSIX timer code is caused by the way the overrun
    accounting works. Depending on interval and expiry time
    values, the overrun can be larger than INT_MAX, but the
    accounting is int based. This basically makes the
    accounting values, which are visible to user space via
    timer_getoverrun(2) and siginfo::si_overrun, random.
    For example, a local user can cause a denial of service
    (signed integer overflow) via crafted mmap, futex,
    timer_create, and timer_settime system
    calls.(CVE-2018-12896)An issue was discovered in the
    proc_pid_stack function in fs/proc/base.c in the Linux
    kernel through 4.18.11. It does not ensure that only
    root may inspect the kernel stack of an arbitrary task,
    allowing a local attacker to exploit racy stack
    unwinding and leak kernel task stack
    contents.(CVE-2018-17972)An issue was discovered in the
    Linux kernel through 4.19. An information leak in
    cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could
    be used by local attackers to read kernel memory
    because a cast from unsigned long to int interferes
    with bounds checking. This is similar to CVE-2018-10940
    and CVE-2018-16658.(CVE-2018-18710 )An issue was
    discovered in the Linux kernel before 4.18.11. The
    ipddp_ioctl function in drivers et/appletalk/ipddp.c
    allows local users to obtain sensitive kernel address
    information by leveraging CAP_NET_ADMIN to read the
    ipddp_route dev and next fields via an SIOCFINDIPDDPRT
    ioctl call.(CVE-2018-20511)An issue was discovered in
    the Linux kernel before 4.18.7. In block/blk-core.c,
    there is an __blk_drain_queue() use-after-free because
    a certain error case is mishandled.(CVE-2018-20856)An
    issue was discovered in fs/xfs/xfs_super.c in the Linux
    kernel before 4.18. A use after free exists, related to
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
    commands.(CVE-2018-6412)In nfc_llcp_build_sdreq_tlv of
    llcp_commands.c, there is a possible out of bounds
    write due to a missing bounds check. This could lead to
    local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android
    kernel. Android ID: A-73083945.(CVE-2018-9518
    )Insufficient access control in the Intel(R)
    PROSet/Wireless WiFi Software driver before version
    21.10 may allow an unauthenticated user to potentially
    enable denial of service via adjacent
    access.(CVE-2019-0136)A vulnerability was found in
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
    security affects.(CVE-2019-10142)An information
    disclosure vulnerability exists when certain central
    processing units (CPU) speculatively access memory, aka
    'Windows Kernel Information Disclosure Vulnerability'.
    This CVE ID is unique from CVE-2019-1071,
    CVE-2019-1073.(CVE-2019-1125)** DISPUTED ** An issue
    was discovered in ip6_ra_control in
    net/ipv6/ipv6_sockglue.c in the Linux kernel through
    5.1.5. There is an unchecked kmalloc of new_ra, which
    might allow an attacker to cause a denial of service
    (NULL pointer dereference and system crash). NOTE: This
    has been disputed as not an issue.(CVE-2019-12378)**
    DISPUTED ** An issue was discovered in
    con_insert_unipair in drivers/tty/vt/consolemap.c in
    the Linux kernel through 5.1.5. There is a memory leak
    in a certain case of an ENOMEM outcome of kmalloc.
    NOTE: This id is disputed as not being an
    issue.(CVE-2019-12379)** DISPUTED ** An issue was
    discovered in ip_ra_control in net/ipv4/ip_sockglue.c
    in the Linux kernel through 5.1.5. There is an
    unchecked kmalloc of new_ra, which might allow an
    attacker to cause a denial of service (NULL pointer
    dereference and system crash). NOTE: this is disputed
    because new_ra is never used if it is
    NULL.(CVE-2019-12381)** DISPUTED ** An issue was
    discovered in the MPT3COMMAND case in _ctl_ioctl_main
    in drivers/scsi/mpt3sas/mpt3sas_ctl.c in the Linux
    kernel through 5.1.5. It allows local users to cause a
    denial of service or possibly have unspecified other
    impact by changing the value of ioc_number between two
    kernel reads of that value, aka a 'double fetch'
    vulnerability. NOTE: a third party reports that this is
    unexploitable because the doubly fetched value is not
    used.(CVE-2019-12456)An issue was discovered in the
    Linux kernel before 4.20.15. The nfc_llcp_build_tlv
    function in net fc/llcp_commands.c may return NULL. If
    the caller does not check for this, it will trigger a
    NULL pointer dereference. This will cause denial of
    service. This affects nfc_llcp_build_gb in net
    fc/llcp_core.c.(CVE-2019-12818)In
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
    discovered in the Linux kernel before 5.0.14. There is
    a NULL pointer dereference caused by a malicious USB
    device in the drivers/usb/misc/yurex.c
    driver.(CVE-2019-15216)An issue was discovered in the
    Linux kernel before 5.2.3. There is a NULL pointer
    dereference caused by a malicious USB device in the
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
    sound/usb/line6/pcm.c driver.(CVE-2019-15221)An issue
    was discovered in the Linux kernel through 5.2.9. There
    is a NULL pointer dereference caused by a malicious USB
    device in the flexcop_usb_probe function in the
    drivers/media/usb/b2c2/flexcop-usb.c
    driver.(CVE-2019-15291)An issue was discovered in the
    Linux kernel before 5.0.9. There is a use-after-free in
    atalk_proc_exit, related to net/appletalk/atalk_proc.c,
    net/appletalk/ddp.c, and
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
    ath6kl_wmi_cac_event_rx in the file drivers
    et/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)An issue
    was discovered in the Linux kernel before 4.20.2. An
    out-of-bounds access exists in the function
    build_audio_procunit in the file
    sound/usb/mixer.c.(CVE-2019-15927)drivers
    et/wireless/marvell/libertas/if_sdio.c in the Linux
    kernel 5.2.14 does not check the alloc_workqueue return
    value, leading to a NULL pointer
    dereference.(CVE-2019-16232)An issue was discovered in
    the Linux kernel before 5.0.4. The 9p filesystem did
    not protect i_size_write() properly, which causes an
    i_size_read() infinite loop and denial of service on
    SMP systems.(CVE-2019-16413)ax25_create in
    net/ax25/af_ax25.c in the AF_AX25 network module in the
    Linux kernel through 5.3.2 does not enforce
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
    CID-3a359798b176.(CVE-2019-17056)An issue was
    discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance.(CVE-2019-17075)In the Linux kernel
    through 5.3.2, cfg80211_mgd_wext_giwessid in
    net/wireless/wext-sme.c does not reject a long SSID IE,
    leading to a Buffer
    Overflow.(CVE-2019-17133)rtl_p2p_noa_ie in drivers
    et/wireless/realtek/rtlwifi/ps.c in the Linux kernel
    through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer overflow.(CVE-2019-17666)In
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
    3.10, 4.14 and 4.18 are vulnerable.(CVE-2019-3882)**
    RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.Note:This vulnarability was lead by
    this commit
    below:5b435de0d786869c95d1962121af0d7df2542009, EulerOS
    kernel doesn't contain this commit.(CVE-2019-9503)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2353
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49df271c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.62.59.83.h195",
        "kernel-debug-3.10.0-327.62.59.83.h195",
        "kernel-debug-devel-3.10.0-327.62.59.83.h195",
        "kernel-debuginfo-3.10.0-327.62.59.83.h195",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h195",
        "kernel-devel-3.10.0-327.62.59.83.h195",
        "kernel-headers-3.10.0-327.62.59.83.h195",
        "kernel-tools-3.10.0-327.62.59.83.h195",
        "kernel-tools-libs-3.10.0-327.62.59.83.h195",
        "perf-3.10.0-327.62.59.83.h195",
        "python-perf-3.10.0-327.62.59.83.h195"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
