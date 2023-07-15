#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135525);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2014-3180",
    "CVE-2014-9888",
    "CVE-2017-12134",
    "CVE-2017-13216",
    "CVE-2017-13693",
    "CVE-2017-7346",
    "CVE-2017-8068",
    "CVE-2017-8069",
    "CVE-2017-8070",
    "CVE-2018-12207",
    "CVE-2018-14633",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-10126",
    "CVE-2019-10220",
    "CVE-2019-11135",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-14901",
    "CVE-2019-15291",
    "CVE-2019-16230",
    "CVE-2019-16231",
    "CVE-2019-16232",
    "CVE-2019-18675",
    "CVE-2019-18805",
    "CVE-2019-18806",
    "CVE-2019-19054",
    "CVE-2019-19056",
    "CVE-2019-19057",
    "CVE-2019-19060",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19066",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19227",
    "CVE-2019-19332",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19527",
    "CVE-2019-19528",
    "CVE-2019-19530",
    "CVE-2019-19531",
    "CVE-2019-19532",
    "CVE-2019-19533",
    "CVE-2019-19534",
    "CVE-2019-19536",
    "CVE-2019-19537",
    "CVE-2019-19768",
    "CVE-2019-19922",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20054",
    "CVE-2019-20096",
    "CVE-2019-2215",
    "CVE-2019-5108",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-8992",
    "CVE-2020-9383"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2020-1396)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - drivers/gpu/drm/radeon/radeon_display.c in the Linux
    kernel 5.2.14 does not check the alloc_workqueue return
    value, leading to a NULL pointer dereference. NOTE: A
    third-party software maintainer states that the work
    queue allocation is happening during device
    initialization, which for a graphics card occurs during
    boot. It is not attacker controllable and OOM at that
    time is highly unlikely.(CVE-2019-16230)

  - In the Linux kernel 5.4.0-rc2, there is a
    use-after-free (read) in the __blk_add_trace function
    in kernel/trace/blktrace.c (which is used to fill out a
    blk_io_trace structure and place it in a per-cpu
    sub-buffer).(CVE-2019-19768)

  - A flaw was discovered in the way that the KVM
    hypervisor handled instruction emulation for an L2
    guest when nested virtualisation is enabled. Under some
    circumstances, an L2 guest may trick the L0 guest into
    accessing sensitive L1 resources that should be
    inaccessible to the L2 guest.(CVE-2020-2732)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c.(CVE-2020-8648)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vgacon_invert_region
    function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)

  - ext4_protect_reserved_inode in fs/ext4/block_validity.c
    in the Linux kernel through 5.5.3 allows attackers to
    cause a denial of service (soft lockup) via a crafted
    journal size.(CVE-2020-8992)

  - An issue was discovered in the Linux kernel through
    5.5.6. set_fdc in drivers/block/floppy.c leads to a
    wait_til_ready out-of-bounds read because the FDC index
    is not checked for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)

  - In kernel/compat.c in the Linux kernel before 3.17, as
    used in Google Chrome OS and other products, there is a
    possible out-of-bounds read. restart_syscall uses
    uninitialized data when restarting
    compat_sys_nanosleep. NOTE: this is disputed because
    the code path is unreachable.(CVE-2014-3180)

  - A heap-based buffer overflow vulnerability was found in
    the Linux kernel, version kernel-2.6.32, in Marvell
    WiFi chip driver. A remote attacker could cause a
    denial of service (system crash) or, possibly execute
    arbitrary code, when the lbs_ibss_join_existing
    function is called after a STA connects to an
    AP.(CVE-2019-14896)

  - A stack-based buffer overflow was found in the Linux
    kernel, version kernel-2.6.32, in Marvell WiFi chip
    driver. An attacker is able to cause a denial of
    service (system crash) or, possibly execute arbitrary
    code, when a STA works in IBSS mode (allows connecting
    stations together without the use of an AP) and
    connects to another STA.(CVE-2019-14897)

  - An out-of-bounds memory write issue was found in the
    Linux Kernel, version 3.13 through 5.4, in the way the
    Linux kernel's KVM hypervisor handled the
    'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or
    process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of
    service.(CVE-2019-19332)

  - In the Linux kernel before 5.3.9, there are multiple
    out-of-bounds write bugs that can be caused by a
    malicious USB device in the Linux kernel HID drivers,
    aka CID-d9d4b1e46d95. This affects
    drivers/hid/hid-axff.c, drivers/hid/hid-dr.c,
    drivers/hid/hid-emsff.c, drivers/hid/hid-gaff.c,
    drivers/hid/hid-holtekff.c, drivers/hid/hid-lg2ff.c,
    drivers/hid/hid-lg3ff.c, drivers/hid/hid-lg4ff.c,
    drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c,
    drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c,
    drivers/hid/hid-tmff.c, and
    drivers/hid/hid-zpff.c.(CVE-2019-19532)

  - kernel/sched/fair.c in the Linux kernel before 5.3.9,
    when cpu.cfs_quota_us is used (e.g., with Kubernetes),
    allows attackers to cause a denial of service against
    non-cpu-bound applications by generating a workload
    that triggers unwanted slice expiration, aka
    CID-de53fd7aedb1. (In other words, although this slice
    expiration would typically be seen with benign
    workloads, it is possible that an attacker could
    calculate how many stray requests are required to force
    an entire Kubernetes cluster into a low-performance
    state caused by slice expiration, and ensure that a
    DDoS attack sent that number of stray requests. An
    attack does not affect the stability of the kernel it
    only causes mismanagement of application
    execution.)(CVE-2019-19922)

  - In the Linux kernel through 5.4.6, there is a NULL
    pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of
    mishandling of port disconnection during discovery,
    related to a PHY down race condition, aka
    CID-f70267f379b5.(CVE-2019-19965)

  - In the Linux kernel before 5.1.6, there is a
    use-after-free in cpia2_exit() in
    drivers/media/usb/cpia2/cpia2_v4l.c that will cause
    denial of service, aka
    CID-dea37a972655.(CVE-2019-19966)

  - In the Linux kernel before 5.0.6, there is a NULL
    pointer dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka
    CID-23da9588037e.(CVE-2019-20054)

  - An exploitable denial-of-service vulnerability exists
    in the Linux kernel prior to mainline 5.3. An attacker
    could exploit this vulnerability by triggering AP to
    send IAPP location updates for stations before the
    required authentication process has completed. This
    could lead to different denial-of-service scenarios,
    either by causing CAM table attacks, or by leading to
    traffic flapping if faking already existing clients in
    other nearby APs of the same wireless infrastructure.
    An attacker can forge Authentication and Association
    Request packets to trigger this
    vulnerability.(CVE-2019-5108)

  - In the Linux kernel before 5.1, there is a memory leak
    in __feat_register_sp() in net/dccp/feat.c, which may
    cause denial of service, aka
    CID-1d3ff0950e2b.(CVE-2019-20096)

  - Improper invalidation for page table updates by a
    virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to
    potentially enable denial of service of the host system
    via local access.(CVE-2018-12207)

  - Insufficient access control in subsystem for Intel (R)
    processor graphics in 6th, 7th, 8th and 9th Generation
    Intel(R) Core(TM) Processor Families Intel(R)
    Pentium(R) Processor J, N, Silver and Gold Series
    Intel(R) Celeron(R) Processor J, N, G3900 and G4900
    Series Intel(R) Atom(R) Processor A and E3900 Series
    Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100
    Processor Families may allow an authenticated user to
    potentially enable denial of service via local
    access.(CVE-2019-0154)

  - Insufficient access control in a subsystem for Intel
    (R) processor graphics in 6th, 7th, 8th and 9th
    Generation Intel(R) Core(TM) Processor Families
    Intel(R) Pentium(R) Processor J, N, Silver and Gold
    Series Intel(R) Celeron(R) Processor J, N, G3900 and
    G4900 Series Intel(R) Atom(R) Processor A and E3900
    Series Intel(R) Xeon(R) Processor E3-1500 v5 and v6,
    E-2100 and E-2200 Processor Families Intel(R) Graphics
    Driver for Windows before 26.20.100.6813 (DCH) or
    26.20.100.6812 and before 21.20.x.5077 (aka15.45.5077),
    i915 Linux Driver for Intel(R) Processor Graphics
    before versions 5.4-rc7, 5.3.11, 4.19.84, 4.14.154,
    4.9.201, 4.4.201 may allow an authenticated user to
    potentially enable escalation of privilege via local
    access.(CVE-2019-0155)

  - TSX Asynchronous Abort condition on some CPUs utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access.(CVE-2019-11135)

  - Linux kernel CIFS implementation, version 4.9.0 is
    vulnerable to a relative paths injection in directory
    entry lists.(CVE-2019-10220)

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

  - The vmw_gb_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel through 4.10.7 does not validate certain levels
    data, which allows local users to cause a denial of
    service (system hang) via a crafted ioctl call for a
    /dev/dri/renderD* device.(CVE-2017-7346)

  - A heap-based buffer overflow was discovered in the
    Linux kernel, all versions 3.x.x and 4.x.x before
    4.18.0, in Marvell WiFi chip driver. The flaw could
    occur when the station attempts a connection
    negotiation during the handling of the remote devices
    country settings. This could allow the remote device to
    cause a denial of service (system crash) or possibly
    execute arbitrary code.(CVE-2019-14895)

  - An issue was discovered in the Linux kernel through
    5.2.9. There is a NULL pointer dereference caused by a
    malicious USB device in the flexcop_usb_probe function
    in the drivers/media/usb/b2c2/flexcop-usb.c
    driver.(CVE-2019-15291)

  - The Linux kernel through 5.3.13 has a start_offset+size
    Integer Overflow in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has
    its own mmap implementation. This allows local users
    (with /dev/video0 access) to obtain read and write
    permissions on kernel physical pages, which can
    possibly result in a privilege
    escalation.(CVE-2019-18675)

  - In the AppleTalk subsystem in the Linux kernel before
    5.1, there is a potential NULL pointer dereference
    because register_snap_client may return NULL. This will
    lead to denial of service in net/appletalk/aarp.c and
    net/appletalk/ddp.c, as demonstrated by
    unregister_snap_client, aka
    CID-9804501fa122.(CVE-2019-19227)

  - In the Linux kernel before 5.3.7, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/usb/misc/adutux.c driver, aka
    CID-44efc269db79.(CVE-2019-19523)

  - In the Linux kernel before 5.3.12, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/input/ff-memless.c driver,
    aka CID-fa3a5a1880c9.(CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/hid/usbhid/hiddev.c driver,
    aka CID-9c09b214f30e.(CVE-2019-19527)

  - In the Linux kernel before 5.3.7, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/usb/misc/iowarrior.c driver,
    aka CID-edc4746f253d.(CVE-2019-19528)

  - In the Linux kernel before 5.2.10, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/usb/class/cdc-acm.c driver,
    aka CID-c52873e5a1ef.(CVE-2019-19530)

  - In the Linux kernel before 5.2.9, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/usb/misc/yurex.c driver, aka
    CID-fc05481b2fca.(CVE-2019-19531)

  - In the Linux kernel before 5.3.4, there is an info-leak
    bug that can be caused by a malicious USB device in the
    drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka
    CID-a10feaf8c464.(CVE-2019-19533)

  - In the Linux kernel before 5.3.11, there is an
    info-leak bug that can be caused by a malicious USB
    device in the
    drivers/net/can/usb/peak_usb/pcan_usb_core.c driver,
    aka CID-f7a1337f0d29.(CVE-2019-19534)

  - In the Linux kernel before 5.2.10, there is a race
    condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka
    CID-303911cfc5b9. This affects
    drivers/usb/core/file.c.(CVE-2019-19536)

  - In the Linux kernel before 5.2.10, there is a race
    condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka
    CID-303911cfc5b9. This affects
    drivers/usb/core/file.c.(CVE-2019-19537)

  - The xen_biovec_phys_mergeable function in
    drivers/xen/biomerge.c in Xen might allow local OS
    guest users to corrupt block device data streams and
    consequently obtain sensitive memory information, cause
    a denial of service, or gain host OS privileges by
    leveraging incorrect block IO merge-ability
    calculation.(CVE-2017-12134)

  - In ashmem_ioctl of ashmem.c, there is an out-of-bounds
    write due to insufficient locking when accessing asma.
    This could lead to a local elevation of privilege
    enabling code execution as a privileged process with no
    additional execution privileges needed. User
    interaction is not needed for exploitation. Product:
    Android. Versions: Android kernel. Android ID:
    A-66954097.(CVE-2017-13216)

  - The acpi_ds_create_operands() function in
    drivers/acpi/acpica/dsutils.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13693)

  - drivers/net/usb/pegasus.c in the Linux kernel 4.9.x
    before 4.9.11 interacts incorrectly with the
    CONFIG_VMAP_STACK option, which allows local users to
    cause a denial of service (system crash or memory
    corruption) or possibly have unspecified other impact
    by leveraging use of more than one virtual page for a
    DMA scatterlist.(CVE-2017-8068)

  - drivers/net/usb/rtl8150.c in the Linux kernel 4.9.x
    before 4.9.11 interacts incorrectly with the
    CONFIG_VMAP_STACK option, which allows local users to
    cause a denial of service (system crash or memory
    corruption) or possibly have unspecified other impact
    by leveraging use of more than one virtual page for a
    DMA scatterlist.(CVE-2017-8069)

  - drivers/net/usb/catc.c in the Linux kernel 4.9.x before
    4.9.11 interacts incorrectly with the CONFIG_VMAP_STACK
    option, which allows local users to cause a denial of
    service (system crash or memory corruption) or possibly
    have unspecified other impact by leveraging use of more
    than one virtual page for a DMA
    scatterlist.(CVE-2017-8070)

  - A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in the Linux kernel in a way an authentication
    request from an ISCSI initiator is processed. An
    unauthenticated remote attacker can cause a stack
    buffer overflow and smash up to 17 bytes of the stack.
    The attack requires the iSCSI target to be enabled on
    the victim host. Depending on how the target's code was
    built (i.e. depending on a compiler, compile flags and
    hardware architecture) an attack may lead to a system
    crash and thus to a denial-of-service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely. Kernel versions 4.18.x,
    4.14.x and 3.10.x are believed to be
    vulnerable.(CVE-2018-14633)

  - A flaw was found in the Linux kernel. A heap based
    buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead
    to memory corruption and possibly other
    consequences.(CVE-2019-10126)

  - An issue was discovered in net/ipv4/sysctl_net_ipv4.c
    in the Linux kernel before 5.0.11. There is a
    net/ipv4/tcp_input.c signed integer overflow in
    tcp_ack_update_rtt() when userspace writes a very large
    integer to /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading
    to a denial of service or possibly unspecified other
    impact, aka CID-19fad20d15a6.(CVE-2019-18805)

  - A memory leak in the ql_alloc_large_buffers() function
    in drivers/net/ethernet/qlogic/qla3xxx.c in the Linux
    kernel before 5.3.5 allows local users to cause a
    denial of service (memory consumption) by triggering
    pci_dma_mapping_error() failures, aka
    CID-1acb8f2a7a9f.(CVE-2019-18806)

  - A use-after-free in binder.c allows an elevation of
    privilege from an application to the Linux Kernel. No
    user interaction is required to exploit this
    vulnerability, however exploitation does require either
    the installation of a malicious local application or a
    separate vulnerability in a network facing
    application.Product: AndroidAndroid ID:
    A-141720095(CVE-2019-2215)

  - arch/arm/mm/dma-mapping.c in the Linux kernel before
    3.13 on ARM platforms, as used in Android before
    2016-08-05 on Nexus 5 and 7 (2013) devices, does not
    prevent executable DMA mappings, which might allow
    local users to gain privileges via a crafted
    application, aka Android internal bug 28803642 and
    Qualcomm internal bug CR642735.(CVE-2014-9888)

  - A memory leak in the cx23888_ir_probe() function in
    drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka
    CID-a7b2df76b42b.(CVE-2019-19054)

  - A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf()
    function in drivers/net/wireless/marvell/mwifiex/pcie.c
    in the Linux kernel through 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering mwifiex_map_pci_memory() failures, aka
    CID-db8fd2cde932.(CVE-2019-19056)

  - Two memory leaks in the mwifiex_pcie_init_evt_ring()
    function in drivers/net/wireless/marvell/mwifiex/pcie.c
    in the Linux kernel through 5.3.11 allow attackers to
    cause a denial of service (memory consumption) by
    triggering mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e.(CVE-2019-19057)

  - A memory leak in the adis_update_scan_mode() function
    in drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-ab612b1daf41.(CVE-2019-19060)

  - A memory leak in the crypto_report() function in
    crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering(CVE-2019-19062)

  - Two memory leaks in the rtl_usb_probe() function in
    drivers/net/wireless/realtek/rtlwifi/usb.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption), aka
    CID-3f9361695113.(CVE-2019-19063)

  - A memory leak in the bfad_im_get_stats() function in
    drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka
    CID-0e62395da2bd.(CVE-2019-19066)

  - Memory leaks in
    drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption) by triggering
    wait_for_completion_timeout() failures. This affects
    the htc_config_pipe_credits() function, the
    htc_setup_complete() function, and the
    htc_connect_service() function, aka
    CID-853acf7caf10.(CVE-2019-19073)

  - A memory leak in the ath9k_wmi_cmd() function in
    drivers/net/wireless/ath/ath9k/wmi.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption), aka
    CID-728c1e2a05e4.(CVE-2019-19074)

  - drivers/net/fjes/fjes_main.c in the Linux kernel 5.2.14
    does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference.(CVE-2019-16231)

  - drivers/net/wireless/marvell/libertas/if_sdio.c in the
    Linux kernel 5.2.14 does not check the alloc_workqueue
    return value, leading to a NULL pointer
    dereference.(CVE-2019-16232)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1396
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f67439f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Binder Use-After-Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h254",
        "kernel-debuginfo-3.10.0-514.44.5.10.h254",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h254",
        "kernel-devel-3.10.0-514.44.5.10.h254",
        "kernel-headers-3.10.0-514.44.5.10.h254",
        "kernel-tools-3.10.0-514.44.5.10.h254",
        "kernel-tools-libs-3.10.0-514.44.5.10.h254",
        "perf-3.10.0-514.44.5.10.h254",
        "python-perf-3.10.0-514.44.5.10.h254"];

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
