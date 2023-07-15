#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134387);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id(
    "CVE-2012-3400",
    "CVE-2013-2164",
    "CVE-2013-2206",
    "CVE-2013-6282",
    "CVE-2018-16880",
    "CVE-2018-20836",
    "CVE-2019-3701",
    "CVE-2019-3819",
    "CVE-2019-3846",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-8956",
    "CVE-2019-9455",
    "CVE-2019-11486",
    "CVE-2019-11487",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11811",
    "CVE-2019-11815",
    "CVE-2019-11833",
    "CVE-2019-12378",
    "CVE-2019-12380",
    "CVE-2019-12381",
    "CVE-2019-12382",
    "CVE-2019-12455",
    "CVE-2019-12456",
    "CVE-2019-12614",
    "CVE-2019-12615",
    "CVE-2019-13233",
    "CVE-2019-13272",
    "CVE-2019-13631",
    "CVE-2019-14283",
    "CVE-2019-15118",
    "CVE-2019-15211",
    "CVE-2019-15214",
    "CVE-2019-15218",
    "CVE-2019-15219",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15292",
    "CVE-2019-15538",
    "CVE-2019-15666",
    "CVE-2019-15807",
    "CVE-2019-15917",
    "CVE-2019-15919",
    "CVE-2019-15920",
    "CVE-2019-15925",
    "CVE-2019-16413",
    "CVE-2019-18805"
  );
  script_bugtraq_id(
    54279,
    60375,
    60715,
    63734
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/06");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1186)");

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
    output, etc.Security Fix(es):Heap-based buffer overflow
    in the udf_load_logicalvol function in fs/udf/super.c
    in the Linux kernel before 3.4.5 allows remote
    attackers to cause a denial of service (system crash)
    or possibly have unspecified other impact via a crafted
    UDF filesystem.(CVE-2012-3400)The
    mmc_ioctl_cdrom_read_data function in
    drivers/cdrom/cdrom.c in the Linux kernel through 3.10
    allows local users to obtain sensitive information from
    kernel memory via a read operation on a malfunctioning
    CD-ROM drive.(CVE-2013-2164)The
    sctp_sf_do_5_2_4_dupcook function in
    net/sctp/sm_statefuns.c in the SCTP implementation in
    the Linux kernel before 3.8.5 does not properly handle
    associations during the processing of a duplicate
    COOKIE ECHO chunk, which allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via crafted SCTP traffic.(CVE-2013-2206)The (1)
    get_user and (2) put_user API functions in the Linux
    kernel before 3.5.5 on the v6k and v7 ARM platforms do
    not validate certain addresses, which allows attackers
    to read or modify the contents of arbitrary kernel
    memory locations via a crafted application, as
    exploited in the wild against Android devices in
    October and November 2013.(CVE-2013-6282)An issue was
    discovered in the Linux kernel before 4.20. There is a
    race condition in smp_task_timedout() and
    smp_task_done() in drivers/scsi/libsas/sas_expander.c,
    leading to a use-after-free.(CVE-2018-20836)The Siemens
    R3964 line discipline driver in drivers/tty/n_r3964.c
    in the Linux kernel before 5.0.8 has multiple race
    conditions.(CVE-2019-11486)The Linux kernel before
    5.1-rc5 allows page->_refcount reference count
    overflow, with resultant use-after-free issues, if
    about 140 GiB of RAM exists. This is related to
    fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h,
    kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It
    can occur with FUSE requests.(CVE-2019-11487)The
    coredump implementation in the Linux kernel before
    5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs,
    which allows local users to obtain sensitive
    information, cause a denial of service, or possibly
    have unspecified other impact by triggering a race
    condition with mmget_not_zero or get_task_mm calls.
    This is related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and
    drivers/infiniband/core/uverbs_main.c.(CVE-2019-11599)A
    n issue was discovered in the Linux kernel before
    5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in
    megasas_alloc_cmds() in
    drivers/scsi/megaraid/megaraid_sas_base.c. This causes
    a Denial of Service, related to a
    use-after-free.(CVE-2019-11810)An issue was discovered
    in the Linux kernel before 5.0.4. There is a
    use-after-free upon attempted read access to
    /proc/ioports after the ipmi_si module is removed,
    related to drivers/char/ipmi/ipmi_si_intf.c,
    drivers/char/ipmi/ipmi_si_mem_io.c, and
    drivers/char/ipmi/ipmi_si_port_io.c.(CVE-2019-11811)A
    flaw was found in the Linux kernel's handle_rx()
    function in the [vhost_net] driver. A malicious virtual
    guest, under specific conditions, can trigger an
    out-of-bounds write in a kmalloc-8 slab on a virtual
    host which may lead to a kernel memory corruption and a
    system panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out. Versions from
    v4.16 and newer are vulnerable.(CVE-2018-16880)An issue
    was discovered in rds_tcp_kill_sock in net/rds/tcp.c in
    the Linux kernel before 5.0.8. There is a race
    condition leading to a use-after-free, related to net
    namespace cleanup.(CVE-2019-11815)A flaw was found in
    the Linux kernel in the function
    hid_debug_events_read() in drivers/hid/hid-debug.c file
    which may enter an infinite loop with certain
    parameters passed from a userspace. A local privileged
    user ('root') can cause a system lock up and a denial
    of service. Versions from v4.18 and newer are
    vulnerable.(CVE-2019-3819)A flaw was found in the Linux
    kernel's vfio interface implementation that permits
    violation of the user's locked memory limit. If a
    device is bound to a vfio driver, such as vfio-pci, and
    the local attacker is administratively granted
    ownership of the device, it may cause a system memory
    exhaustion and thus a denial of service (DoS). Versions
    3.10, 4.14 and 4.18 are vulnerable.(CVE-2019-3882)An
    infinite loop issue was found in the vhost_net kernel
    module in Linux Kernel up to and including v5.1-rc6,
    while handling incoming packets in handle_rx(). It
    could occur if one end sends packets faster than the
    other end can process them. A guest user, maybe remote
    one, could use this flaw to stall the vhost_net kernel
    thread, resulting in a DoS scenario.(CVE-2019-3900)In
    the Linux Kernel before versions 4.20.8 and 4.19.21 a
    use-after-free error in the 'sctp_sendmsg()' function
    (net/sctp/socket.c) when handling SCTP_SENDALL flag can
    be exploited to corrupt memory.(CVE-2019-8956)A flaw
    was found in the Linux kernel's implementation of ext4
    extent management. The kernel doesn't correctly
    initialize memory regions in the extent tree block
    which may be exported to a local user to obtain
    sensitive information by reading empty/uninitialized
    data from the filesystem.(CVE-2019-11833)An issue was
    discovered in drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c in the Linux kernel
    through 5.1.5. There is an unchecked kstrdup of fwstr,
    which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash).
    NOTE: The vendor disputes this issues as not being a
    vulnerability because kstrdup() returning NULL is
    handled sufficiently and there is no chance for a NULL
    pointer dereference.(CVE-2019-12382)An issue was
    discovered in the efi subsystem in the Linux kernel
    through 5.1.5. phys_efi_set_virtual_address_map in
    arch/x86/platform/efi/efi.c and efi_call_phys_prolog in
    arch/x86/platform/efi/efi_64.c mishandle memory
    allocation failures. NOTE: This id is disputed as not
    being an issue because ?All the code touched by the
    referenced commit runs only at boot, before any user
    processes are started. Therefore, there is no
    possibility for an unprivileged user to control
    it.(CVE-2019-12380)An issue was discovered in the Linux
    kernel before 5.2.3. An out of bounds access exists in
    the function hclge_tm_schd_mode_vnet_base_cfg in the
    file drivers
    et/ethernet/hisilicon/hns3/hns3pf/hclge_tm.c.(CVE-2019-
    15925)An issue was discovered in
    dlpar_parse_cc_property in
    arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of
    prop-i1/4zname, which might allow an attacker to cause a
    denial of service (NULL pointer dereference and system
    crash).(CVE-2019-12614)An issue was discovered in
    net/ipv4/sysctl_net_ipv4.c in the Linux kernel before
    5.0.11. There is a net/ipv4/tcp_input.c signed integer
    overflow in tcp_ack_update_rtt() when userspace writes
    a very large integer to
    /proc/syset/ipv4/tcp_min_rtt_wlen, leading to a denial
    of service or possibly unspecified other impact, aka
    CID-19fad20d15a6.(CVE-2019-18805)A flaw was found in
    the way PTRACE_TRACEME functionality was handled in the
    Linux kernel. The kernel's implementation of ptrace can
    inadvertently grant elevated permissions to an attacker
    who can then abuse the relationship between the tracer
    and the process being traced. This flaw could allow a
    local, unprivileged user to increase their privileges
    on the system or cause a denial of
    service.(CVE-2019-13272)An issue was discovered in
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
    sunxi_divs_clk_setup in drivers/clk/sunxi/clk-sunxi.c
    in the Linux kernel through 5.1.5. There is an
    unchecked kstrndup of derived_name, which might allow
    an attacker to cause a denial of service (NULL pointer
    dereference and system crash). NOTE: This id is
    disputed as not being an issue because 'The memory
    allocation that was not checked is part of a code that
    only runs at boot time, before user processes are
    started. Therefore, there is no possibility for an
    unprivileged user to control it, and no denial of
    service.'.(CVE-2019-12455)An issue was discovered in
    the MPT3COMMAND case in _ctl_ioctl_main in
    drivers/scsi/mpt3sas/mpt3sas_ctl.c in the Linux kernel
    through 5.1.5. It allows local users to cause a denial
    of service or possibly have unspecified other impact by
    changing the value of ioc_number between two kernel
    reads of that value, aka a ''double fetch''
    vulnerability. NOTE: a third party reports that this is
    unexploitable because the doubly fetched value is not
    used.(CVE-2019-12456)An issue was discovered in
    get_vdev_port_node_info in arch/sparc/kernel/mdesc.c in
    the Linux kernel through 5.1.6. There is an unchecked
    kstrdup_const of node_info-i1/4zvdev_port.name, which
    might allow an attacker to cause a denial of service
    (NULL pointer dereference and system
    crash).(CVE-2019-12615)In parse_hid_report_descriptor
    in drivers/input/tablet/gtco.c in the Linux kernel
    through 5.2.1, a malicious USB device can send an HID
    report that triggers an out-of-bounds write during
    generation of debugging messages.(CVE-2019-13631)A
    vulnerability was found in the Linux kernelaEURtms floppy
    disk driver implementation. A local attacker with
    access to the floppy device could call set_geometry in
    drivers/block/floppy.c, which does not validate the
    sect and head fields, causing an integer overflow and
    out-of-bounds read. This flaw may crash the system or
    allow an attacker to gather information causing
    subsequent successful
    attacks.(CVE-2019-14283)check_input_term in
    sound/usb/mixer.c in the Linux kernel through 5.2.9
    mishandles recursion, leading to kernel stack
    exhaustion.(CVE-2019-15118)An issue was discovered in
    the Linux kernel before 5.2.6. There is a
    use-after-free caused by a malicious USB device in the
    drivers/media/v4l2-core/v4l2-dev.c driver because
    drivers/media/radio/radio-raremono.c does not properly
    allocate memory.(CVE-2019-15211)An issue was discovered
    in the Linux kernel before 5.0.10. There is a
    use-after-free in the sound subsystem because card
    disconnection causes certain data structures to be
    deleted too early. This is related to sound/core/init.c
    and sound/core/info.c.(CVE-2019-15214)An issue was
    discovered in the Linux kernel before 5.1.8. There is a
    NULL pointer dereference caused by a malicious USB
    device in the drivers/media/usb/siano/smsusb.c
    driver.(CVE-2019-15218)An issue was discovered in the
    Linux kernel before 5.1.8. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/usb/misc/sisusbvga/sisusb.c
    driver.(CVE-2019-15219)An issue was discovered in the
    Linux kernel before 5.2.1. There is a use-after-free
    caused by a malicious USB device in the
    driverset/wireless/intersil/p54/p54usb.c
    driver.(CVE-2019-15220)An issue was discovered in the
    Linux kernel before 5.1.17. There is a NULL pointer
    dereference caused by a malicious USB device in the
    sound/usb/line6/pcm.c driver.(CVE-2019-15221)An issue
    was discovered in the Linux kernel before 5.0.9. There
    is a use-after-free in atalk_proc_exit, related to
    net/appletalk/atalk_proc.c, net/appletalk/ddp.c, and
    net/appletalk/sysctl_net_atalk.c.(CVE-2019-15292)An
    issue was discovered in xfs_setattr_nonsize in
    fs/xfs/xfs_iops.c in the Linux kernel through 5.2.9.
    XFS partially wedges when a chgrp fails on account of
    being out of disk quota. xfs_setattr_nonsize is failing
    to unlock the ILOCK after the xfs_qm_vop_chown_reserve
    call fails. This is primarily a local DoS attack
    vector, but it might result as well in remote DoS if
    the XFS filesystem is exported for instance via
    NFS.(CVE-2019-15538)An issue was discovered in the
    Linux kernel before 5.0.19. There is an out-of-bounds
    array access in __xfrm_policy_unlink, which will cause
    denial of service, because verify_newpolicy_info in
    net/xfrm/xfrm_user.c mishandles directory
    validation.(CVE-2019-15666)In the Linux kernel before
    5.1.13, there is a memory leak in
    drivers/scsi/libsas/sas_expander.c when SAS expander
    discovery fails. This will cause a BUG and denial of
    service.(CVE-2019-15807)An issue was discovered in the
    Linux kernel before 5.0.5. There is a use-after-free
    issue when hci_uart_register_dev() fails in
    hci_uart_set_proto() in
    drivers/bluetooth/hci_ldisc.c.(CVE-2019-15917)An issue
    was discovered in the Linux kernel before 5.0.10.
    SMB2_write in fs/cifs/smb2pdu.c has a
    use-after-free.(CVE-2019-15919)An issue was discovered
    in the Linux kernel before 5.0.10. SMB2_read in
    fs/cifs/smb2pdu.c has a use-after-free. NOTE: this was
    not fixed correctly in 5.0.10 see the 5.0.11 ChangeLog,
    which documents a memory leak.(CVE-2019-15920)An issue
    was discovered in the Linux kernel before 5.0.4. The 9p
    filesystem did not protect i_size_write() properly,
    which causes an i_size_read() infinite loop and denial
    of service on SMP systems.(CVE-2019-16413)An issue was
    discovered in can_can_gw_rcv in net/can/gw.c in the
    Linux kernel through 4.19.13. The CAN frame
    modification rules allow bitwise logical operations
    that can be also applied to the can_dlc field. Because
    of a missing check, the CAN drivers may write arbitrary
    content beyond the data registers in the CAN
    controller's I/O memory when processing can-gw
    manipulated outgoing frames. This is related to
    cgw_csum_xor_rel. An unprivileged user can trigger a
    system crash (general protection
    fault).(CVE-2019-3701)A flaw was found in the Linux
    kernel's Marvell wifi chip driver. A heap overflow in
    mwifiex_update_bss_desc_with_ie function in
    marvell/mwifiex/scan.c allows remote attackers to cause
    a denial of service(system crash) or execute arbitrary
    code.(CVE-2019-3846)A new software page cache side
    channel attack scenario was discovered in operating
    systems that implement the very common 'page cache'
    caching mechanism. A malicious user/process could use
    'in memory' page-cache knowledge to infer access
    timings to shared memory and gain knowledge which can
    be used to reduce effectiveness of cryptographic
    strength by monitoring algorithmic behavior, infer
    access patterns of memory to determine code paths
    taken, and exfiltrate data to a blinded attacker
    through page-granularity access times as a
    side-channel.(CVE-2019-5489)In the Android kernel in
    the video driver there is a kernel pointer leak due to
    a WARN_ON statement. This could lead to local
    information disclosure with System execution privileges
    needed. User interaction is not needed for
    exploitation.(CVE-2019-9455)A vulnerability was found
    in the arch/x86/lib/insn-eval.c function in the Linux
    kernel. An attacker could corrupt the memory due to a
    flaw in use-after-free access to an LDT entry caused by
    a race condition between modify_ldt() and a #BR
    exception for an MPX bounds violation.(CVE-2019-13233)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1186
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d22916d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15292");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Polkit pkexec helper PTRACE_TRACEME local root exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h361.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h361.eulerosv2r8"];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
