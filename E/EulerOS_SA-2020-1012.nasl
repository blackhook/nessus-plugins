#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132605);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-13693",
    "CVE-2017-13694",
    "CVE-2019-10220",
    "CVE-2019-11191",
    "CVE-2019-14901",
    "CVE-2019-15291",
    "CVE-2019-16229",
    "CVE-2019-16231",
    "CVE-2019-16232",
    "CVE-2019-18660",
    "CVE-2019-18675",
    "CVE-2019-18683",
    "CVE-2019-18786",
    "CVE-2019-18808",
    "CVE-2019-18814",
    "CVE-2019-18885",
    "CVE-2019-19045",
    "CVE-2019-19046",
    "CVE-2019-19049",
    "CVE-2019-19051",
    "CVE-2019-19052",
    "CVE-2019-19054",
    "CVE-2019-19056",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19060",
    "CVE-2019-19061",
    "CVE-2019-19063",
    "CVE-2019-19065",
    "CVE-2019-19066",
    "CVE-2019-19067",
    "CVE-2019-19068",
    "CVE-2019-19070",
    "CVE-2019-19071",
    "CVE-2019-19072",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19075",
    "CVE-2019-19077",
    "CVE-2019-19078",
    "CVE-2019-19079",
    "CVE-2019-19080",
    "CVE-2019-19081",
    "CVE-2019-19082",
    "CVE-2019-19083",
    "CVE-2019-19227",
    "CVE-2019-19252",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19525",
    "CVE-2019-19526",
    "CVE-2019-19527",
    "CVE-2019-19528",
    "CVE-2019-19529",
    "CVE-2019-19530",
    "CVE-2019-19531",
    "CVE-2019-19532",
    "CVE-2019-19533",
    "CVE-2019-19534",
    "CVE-2019-19535",
    "CVE-2019-19536",
    "CVE-2019-19537",
    "CVE-2019-19767"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1012)");
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
    output, etc.Security Fix(es):** DISPUTED ** A memory
    leak in the __ipmi_bmc_register() function in
    drivers/char/ipmi/ipmi_msghandler.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    ida_simple_get() failure, aka CID-4aa7afb0ee20. NOTE:
    third parties dispute the relevance of this because an
    attacker cannot realistically control this failure at
    probe time.(CVE-2019-19046)A memory leak in the
    bfad_im_get_stats() function in
    drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka
    CID-0e62395da2bd.(CVE-2019-19066)A memory leak in the
    adis_update_scan_mode_burst() function in
    drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-9c0530e898f3.(CVE-2019-19061)In the Linux kernel
    before 5.3.12, there is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/input/ff-memless.c driver, aka
    CID-fa3a5a1880c9.(CVE-2019-19524)The Linux kernel
    through 5.0.7, when CONFIG_IA32_AOUT is enabled and
    ia32_aout is loaded, allows local users to bypass ASLR
    on setuid a.out programs (if any exist) because
    install_exec_creds() is called too late in
    load_aout_binary() in fs/binfmt_aout.c, and thus the
    ptrace_may_access() check has a race condition when
    reading /proc/pid/stat. NOTE: the software maintainer
    disputes that this is a vulnerability because ASLR for
    a.out format executables has never been
    supported.(CVE-2019-11191)In the Linux kernel before
    5.2.10, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/hid/usbhid/hiddev.c driver, aka
    CID-9c09b214f30e.(CVE-2019-19527)In the Linux kernel
    before 5.3.9, there are multiple out-of-bounds write
    bugs that can be caused by a malicious USB device in
    the Linux kernel HID drivers, aka CID-d9d4b1e46d95.
    This affects drivers/hid/hid-axff.c,
    drivers/hid/hid-dr.c, drivers/hid/hid-emsff.c,
    drivers/hid/hid-gaff.c, drivers/hid/hid-holtekff.c,
    drivers/hid/hid-lg2ff.c, drivers/hid/hid-lg3ff.c,
    drivers/hid/hid-lg4ff.c, drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c,
    drivers/hid/hid-microsoft.c, drivers/hid/hid-sony.c,
    drivers/hid/hid-tmff.c, and
    drivers/hid/hid-zpff.c.(CVE-2019-19532)The
    acpi_ps_complete_final_op() function in
    drivers/acpi/acpica/psobject.c in the Linux kernel
    through 4.12.9 does not flush the node and node_ext
    caches and causes a kernel stack dump, which allows
    local users to obtain sensitive information from kernel
    memory and bypass the KASLR protection mechanism (in
    the kernel through 4.9) via a crafted ACPI
    table.(CVE-2017-13694)The acpi_ds_create_operands()
    function in drivers/acpi/acpica/dsutils.c in the Linux
    kernel through 4.12.9 does not flush the operand cache
    and causes a kernel stack dump, which allows local
    users to obtain sensitive information from kernel
    memory and bypass the KASLR protection mechanism (in
    the kernel through 4.9) via a crafted ACPI
    table.(CVE-2017-13693)The Linux kernel before 5.4.1 on
    powerpc allows Information Exposure because the
    Spectre-RSB mitigation is not in place for all
    applicable CPUs, aka CID-39e72bf96f58. This is related
    to arch/powerpc/kernel/entry_64.S and
    arch/powerpc/kernel/security.c.(CVE-2019-18660)In the
    Linux kernel through 5.3.8, f->fmt.sdr.reserved is
    uninitialized in rcar_drif_g_fmt_sdr_cap in
    drivers/media/platform/rcar_drif.c, which could cause a
    memory disclosure problem.(CVE-2019-18786)An issue was
    discovered in drivers/media/platform/vivid in the Linux
    kernel through 5.3.8. It is exploitable for privilege
    escalation on some Linux distributions where local
    users have /dev/video0 access, but only if the driver
    happens to be loaded. There are multiple race
    conditions during streaming stopping in this driver
    (part of the V4L2 subsystem). These issues are caused
    by wrong mutex locking in
    vivid_stop_generating_vid_cap(),
    vivid_stop_generating_vid_out(),
    sdr_cap_stop_streaming(), and the corresponding
    kthreads. At least one of these race conditions leads
    to a use-after-free.(CVE-2019-18683)A memory leak in
    the cx23888_ir_probe() function in
    drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka
    CID-a7b2df76b42b.(CVE-2019-19054)A memory leak in the
    mlx5_fpga_conn_create_cq() function in drivers
    et/ethernet/mellanox/mlx5/core/fpga/conn.c in the Linux
    kernel before 5.3.11 allows attackers to cause a denial
    of service (memory consumption) by triggering
    mlx5_vector2eqn() failures, aka
    CID-c8c2a057fdc7.(CVE-2019-19045)A memory leak in the
    i2400m_op_rfkill_sw_toggle() function in drivers
    et/wimax/i2400m/op-rfkill.c in the Linux kernel before
    5.3.11 allows attackers to cause a denial of service
    (memory consumption), aka
    CID-6f3ef5c25cc7.(CVE-2019-19051)A memory leak in the
    alloc_sgtable() function in drivers
    et/wireless/intel/iwlwifi/fw/dbg.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering alloc_page()
    failures, aka CID-b4b814fec1a5.(CVE-2019-19058)Multiple
    memory leaks in the iwl_pcie_ctxt_info_gen3_init()
    function in drivers
    et/wireless/intel/iwlwifi/pcie/ctxt-info-gen3.c in the
    Linux kernel through 5.3.11 allow attackers to cause a
    denial of service (memory consumption) by triggering
    iwl_pcie_init_fw_sec() or dma_alloc_coherent()
    failures, aka CID-0f4f199443fa.(CVE-2019-19059)A memory
    leak in the unittest_data_add() function in
    drivers/of/unittest.c in the Linux kernel before 5.3.10
    allows attackers to cause a denial of service (memory
    consumption) by triggering of_fdt_unflatten_tree()
    failures, aka CID-e13de8fe0d6a. NOTE: third parties
    dispute the relevance of this because unittest.c can
    only be reached during boot.(CVE-2019-19049)A memory
    leak in the spi_gpio_probe() function in
    drivers/spi/spi-gpio.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering
    devm_add_action_or_reset() failures, aka
    CID-d3b0ffa1d75d. NOTE: third parties dispute the
    relevance of this because the system must have already
    been out of memory before the probe
    began.(CVE-2019-19070)A memory leak in the sdma_init()
    function in drivers/infiniband/hw/hfi1/sdma.c in the
    Linux kernel before 5.3.9 allows attackers to cause a
    denial of service (memory consumption) by triggering
    rhashtable_init() failures, aka
    CID-34b3be18a04e.(CVE-2019-19065)** DISPUTED ** Four
    memory leaks in the acp_hw_init() function in
    drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c in the Linux
    kernel before 5.3.8 allow attackers to cause a denial
    of service (memory consumption) by triggering
    mfd_add_hotplug_devices() or pm_genpd_add_device()
    failures, aka CID-57be09c6e874. NOTE: third parties
    dispute the relevance of this because the attacker must
    already have privileges for module
    loading.(CVE-2019-19067)A memory leak in the
    rtl8xxxu_submit_int_urb() function in drivers
    et/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c in the
    Linux kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    usb_submit_urb() failures, aka
    CID-a2cdd07488e6.(CVE-2019-19068)A memory leak in the
    rsi_send_beacon() function in drivers
    et/wireless/rsi/rsi_91x_mgmt.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    rsi_prepare_beacon() failures, aka
    CID-d563131ef23c.(CVE-2019-19071)A memory leak in the
    ca8210_probe() function in drivers
    et/ieee802154/ca8210.c in the Linux kernel before 5.3.8
    allows attackers to cause a denial of service (memory
    consumption) by triggering ca8210_get_platform_data()
    failures, aka CID-6402939ec86e.(CVE-2019-19075)A memory
    leak in the bnxt_re_create_srq() function in
    drivers/infiniband/hw/bnxt_re/ib_verbs.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    copy to udata failures, aka
    CID-4a9d46a9fe14.(CVE-2019-19077)A memory leak in the
    ath10k_usb_hif_tx_sg() function in drivers
    et/wireless/ath/ath10k/usb.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    usb_submit_urb() failures, aka
    CID-b8d17e7d93d2.(CVE-2019-19078)A memory leak in the
    qrtr_tun_write_iter() function in net/qrtr/tun.c in the
    Linux kernel before 5.3 allows attackers to cause a
    denial of service (memory consumption), aka
    CID-a21b7f0cff19.(CVE-2019-19079)Four memory leaks in
    the nfp_flower_spawn_phy_reprs() function in drivers
    et/ethernet etronome fp/flower/main.c in the Linux
    kernel before 5.3.4 allow attackers to cause a denial
    of service (memory consumption), aka
    CID-8572cea1461a.(CVE-2019-19080)A memory leak in the
    nfp_flower_spawn_vnic_reprs() function in drivers
    et/ethernet etronome fp/flower/main.c in the Linux
    kernel before 5.3.4 allows attackers to cause a denial
    of service (memory consumption), aka
    CID-8ce39eb5a67a.(CVE-2019-19081)Memory leaks in
    *create_resource_pool() functions under
    drivers/gpu/drm/amd/display/dc in the Linux kernel
    through 5.3.11 allow attackers to cause a denial of
    service (memory consumption). This affects the
    dce120_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce120/dce120_resource.c
    , the dce110_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce110/dce110_resource.c
    , the dce100_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce100/dce100_resource.c
    , the dcn10_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dcn10/dcn10_resource.c,
    and the dce112_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce112/dce112_resource.c
    , aka CID-104c307147ad.(CVE-2019-19082)Memory leaks in
    *clock_source_create() functions under
    drivers/gpu/drm/amd/display/dc in the Linux kernel
    before 5.3.8 allow attackers to cause a denial of
    service (memory consumption). This affects the
    dce112_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce112/dce112_resource.c
    , the dce100_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce100/dce100_resource.c
    , the dcn10_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dcn10/dcn10_resource.c,
    the dcn20_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dcn20/dcn20_resource.c,
    the dce120_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce120/dce120_resource.c
    , the dce110_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce110/dce110_resource.c
    , and the dce80_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce80/dce80_resource.c,
    aka CID-055e547478a1.(CVE-2019-19083)In the Linux
    kernel before 5.2.9, there is an info-leak bug that can
    be caused by a malicious USB device in the drivers
    et/can/usb/peak_usb/pcan_usb_fd.c driver, aka
    CID-30a8beeb3042.(CVE-2019-19535)fs/btrfs/volumes.c in
    the Linux kernel before 5.1 allows a
    btrfs_verify_dev_extents NULL pointer dereference via a
    crafted btrfs image because fs_devices->devices is
    mishandled within find_device, aka
    CID-09ba3bc9dd15.(CVE-2019-18885)In the Linux kernel
    before 5.2.9, there is an info-leak bug that can be
    caused by a malicious USB device in the drivers
    et/can/usb/peak_usb/pcan_usb_pro.c driver, aka
    CID-ead16e53c2f0.(CVE-2019-19536)In the Linux kernel
    before 5.3.6, there is a use-after-free bug that can be
    caused by a malicious USB device in the drivers
    et/ieee802154/atusb.c driver, aka
    CID-7fd25e6fc035.(CVE-2019-19525)In the Linux kernel
    before 5.3.9, there is a use-after-free bug that can be
    caused by a malicious USB device in the drivers
    fc/pn533/usb.c driver, aka
    CID-6af3aa57a098.(CVE-2019-19526)In the Linux kernel
    before 5.3.11, there is a use-after-free bug that can
    be caused by a malicious USB device in the drivers
    et/can/usb/mcba_usb.c driver, aka
    CID-4d6636498c41.(CVE-2019-19529)A memory leak in the
    adis_update_scan_mode() function in
    drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-ab612b1daf41.(CVE-2019-19060)In the Linux kernel
    before 5.3.11, there is an info-leak bug that can be
    caused by a malicious USB device in the drivers
    et/can/usb/peak_usb/pcan_usb_core.c driver, aka
    CID-f7a1337f0d29.(CVE-2019-19534)A memory leak in the
    ccp_run_sha_cmd() function in
    drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-128c66429247.(CVE-2019-18808)drivers
    et/wireless/marvell/libertas/if_sdio.c in the Linux
    kernel 5.2.14 does not check the alloc_workqueue return
    value, leading to a NULL pointer
    dereference.(CVE-2019-16232)drivers et/fjes/fjes_main.c
    in the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer
    dereference.(CVE-2019-16231)** DISPUTED **
    drivers/gpu/drm/amd/amdkfd/kfd_interrupt.c in the Linux
    kernel 5.2.14 does not check the alloc_workqueue return
    value, leading to a NULL pointer dereference. NOTE: The
    security community disputes this issues as not being
    serious enough to be deserving a CVE
    id.(CVE-2019-16229)Linux kernel CIFS implementation,
    version 4.9.0 is vulnerable to a relative paths
    injection in directory entry
    lists.(CVE-2019-10220)Memory leaks in drivers
    et/wireless/ath/ath9k/htc_hst.c in the Linux kernel
    through 5.3.11 allow attackers to cause a denial of
    service (memory consumption) by triggering
    wait_for_completion_timeout() failures. This affects
    the htc_config_pipe_credits() function, the
    htc_setup_complete() function, and the
    htc_connect_service() function, aka
    CID-853acf7caf10.(CVE-2019-19073)Two memory leaks in
    the mwifiex_pcie_init_evt_ring() function in drivers
    et/wireless/marvell/mwifiex/pcie.c in the Linux kernel
    through 5.3.11 allow attackers to cause a denial of
    service (memory consumption) by triggering
    mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e.(CVE-2019-19057)A memory leak in the
    gs_can_open() function in drivers et/can/usb/gs_usb.c
    in the Linux kernel before 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering usb_submit_urb() failures, aka
    CID-fb5be6a7b486.(CVE-2019-19052)A memory leak in the
    mwifiex_pcie_alloc_cmdrsp_buf() function in drivers
    et/wireless/marvell/mwifiex/pcie.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    mwifiex_map_pci_memory() failures, aka
    CID-db8fd2cde932.(CVE-2019-19056)A memory leak in the
    ath9k_wmi_cmd() function in drivers
    et/wireless/ath/ath9k/wmi.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption), aka
    CID-728c1e2a05e4.(CVE-2019-19074)Two memory leaks in
    the rtl_usb_probe() function in drivers
    et/wireless/realtek/rtlwifi/usb.c in the Linux kernel
    through 5.3.11 allow attackers to cause a denial of
    service (memory consumption), aka
    CID-3f9361695113.(CVE-2019-19063)An issue was
    discovered in the Linux kernel through 5.3.9. There is
    a use-after-free when aa_label_parse() fails in
    aa_audit_rule_init() in
    security/apparmor/audit.c.(CVE-2019-18814)A memory leak
    in the predicate_parse() function in
    kernel/trace/trace_events_filter.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-96c5c6e6a5b6.(CVE-2019-19072)In the Linux kernel
    before 5.3.7, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/usb/misc/adutux.c driver, aka
    CID-44efc269db79.(CVE-2019-19523)In the Linux kernel
    before 5.3.7, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/usb/misc/iowarrior.c driver, aka
    CID-edc4746f253d.(CVE-2019-19528)In the Linux kernel
    before 5.2.10, there is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/usb/class/cdc-acm.c driver, aka
    CID-c52873e5a1ef.(CVE-2019-19530)In the Linux kernel
    before 5.3.4, there is an info-leak bug that can be
    caused by a malicious USB device in the
    drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka
    CID-a10feaf8c464.(CVE-2019-19533)In the Linux kernel
    before 5.2.10, there is a race condition bug that can
    be caused by a malicious USB device in the USB
    character device driver layer, aka CID-303911cfc5b9.
    This affects drivers/usb/core/file.c.(CVE-2019-19537)In
    the Linux kernel before 5.2.9, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/usb/misc/yurex.c driver, aka
    CID-fc05481b2fca.(CVE-2019-19531)The Linux kernel
    through 5.3.13 has a start_offset+size Integer Overflow
    in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has
    its own mmap implementation. This allows local users
    (with /dev/video0 access) to obtain read and write
    permissions on kernel physical pages, which can
    possibly result in a privilege
    escalation.(CVE-2019-18675)In the AppleTalk subsystem
    in the Linux kernel before 5.1, there is a potential
    NULL pointer dereference because register_snap_client
    may return NULL. This will lead to denial of service in
    net/appletalk/aarp.c and net/appletalk/ddp.c, as
    demonstrated by unregister_snap_client, aka
    CID-9804501fa122.(CVE-2019-19227)vcs_write in
    drivers/tty/vt/vc_screen.c in the Linux kernel through
    5.3.13 does not prevent write access to vcsu devices,
    aka CID-0c9acb1af77a.(CVE-2019-19252)The Linux kernel
    before 5.4.2 mishandles ext4_expand_extra_isize, as
    demonstrated by use-after-free errors in
    __ext4_expand_extra_isize and ext4_xattr_set_entry,
    related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163.(CVE-2019-19767)A heap overflow flaw
    was found in the Linux kernel, all versions 3.x.x and
    4.x.x before 4.18.0, in Marvell WiFi chip driver. The
    vulnerability allows a remote attacker to cause a
    system crash, resulting in a denial of service, or
    execute arbitrary code. The highest threat with this
    vulnerability is with the availability of the system.
    If code execution occurs, the code will run with the
    permissions of root. This will affect both
    confidentiality and integrity of files on the
    system.(CVE-2019-14901)An issue was discovered in the
    Linux kernel through 5.2.9. There is a NULL pointer
    dereference caused by a malicious USB device in the
    flexcop_usb_probe function in the
    drivers/media/usb/b2c2/flexcop-usb.c
    driver.(CVE-2019-15291)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f83f4799");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/02");

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

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h619.eulerosv2r8"];

foreach (pkg in pkgs)
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
