#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132796);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-0136",
    "CVE-2019-15504",
    "CVE-2019-16089",
    "CVE-2019-16233",
    "CVE-2019-16234",
    "CVE-2019-16714",
    "CVE-2019-16746",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17056",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2019-18683",
    "CVE-2019-18786",
    "CVE-2019-18806",
    "CVE-2019-18808",
    "CVE-2019-18809",
    "CVE-2019-18813",
    "CVE-2019-18814",
    "CVE-2019-19045",
    "CVE-2019-19049",
    "CVE-2019-19051",
    "CVE-2019-19052",
    "CVE-2019-19054",
    "CVE-2019-19056",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19059",
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
    "CVE-2019-19083"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.5.0 : kernel (EulerOS-SA-2020-1042)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - drivers/net/wireless/rsi/rsi_91x_usb.c in the Linux
    kernel through 5.2.9 has a Double Free via crafted USB
    device traffic (which may be remote via usbip or
    usbredir).(CVE-2019-15504)

  - In the Linux kernel before 5.2.14, rds6_inc_info_copy
    in net/rds/recv.c allows attackers to obtain sensitive
    information from kernel stack memory because tos and
    flags fields are not initialized.(CVE-2019-16714)

  - drivers/scsi/qla2xxx/qla_os.c in the Linux kernel
    5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference.(CVE-2019-16233)

  - An issue was discovered in the Linux kernel through
    5.2.13. nbd_genl_status in drivers/block/nbd.c does not
    check the nla_nest_start_noflag return
    value.(CVE-2019-16089)

  - llcp_sock_create in net/nfc/llcp_sock.c in the AF_NFC
    network module in the Linux kernel through 5.3.2 does
    not enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-3a359798b176.(CVE-2019-17056)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the
    AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that
    unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21.(CVE-2019-17055)

  - atalk_create in net/appletalk/ddp.c in the AF_APPLETALK
    network module in the Linux kernel through 5.3.2 does
    not enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-6cc03e8aa36c.(CVE-2019-17054)

  - ieee802154_create in net/ieee802154/socket.c in the
    AF_IEEE802154 network module in the Linux kernel
    through 5.3.2 does not enforce CAP_NET_RAW, which means
    that unprivileged users can create a raw socket, aka
    CID-e69dbd4619e7.(CVE-2019-17053)

  - ax25_create in net/ax25/af_ax25.c in the AF_AX25
    network module in the Linux kernel through 5.3.2 does
    not enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-0614e2b73768.(CVE-2019-17052)

  - An issue was discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance.(CVE-2019-17075)

  - rtl_p2p_noa_ie in
    drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux
    kernel through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer overflow.(CVE-2019-17666)

  - In the Linux kernel through 5.3.2,
    cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c
    does not reject a long SSID IE, leading to a Buffer
    Overflow.(CVE-2019-17133)

  - An issue was discovered in net/wireless/nl80211.c in
    the Linux kernel through 5.2.17. It does not check the
    length of variable elements in a beacon head, leading
    to a buffer overflow.(CVE-2019-16746)

  - Insufficient access control in the Intel(R)
    PROSet/Wireless WiFi Software driver before version
    21.10 may allow an unauthenticated user to potentially
    enable denial of service via adjacent
    access.(CVE-2019-0136)

  - drivers/net/wireless/intel/iwlwifi/pcie/trans.c in the
    Linux kernel 5.2.14 does not check the alloc_workqueue
    return value, leading to a NULL pointer
    dereference.(CVE-2019-16234)

  - A memory leak in the ql_alloc_large_buffers() function
    in drivers/net/ethernet/qlogic/qla3xxx.c in the Linux
    kernel before 5.3.5 allows local users to cause a
    denial of service (memory consumption) by triggering
    pci_dma_mapping_error() failures, aka
    CID-1acb8f2a7a9f.(CVE-2019-18806)

  - A memory leak in the dwc3_pci_probe() function in
    drivers/usb/dwc3/dwc3-pci.c in the Linux kernel through
    5.3.9 allows attackers to cause a denial of service
    (memory consumption) by triggering
    platform_device_add_properties() failures, aka
    CID-9bbfceea12a8.(CVE-2019-18813)

  - A memory leak in the af9005_identify_state() function
    in drivers/media/usb/dvb-usb/af9005.c in the Linux
    kernel through 5.3.9 allows attackers to cause a denial
    of service (memory consumption), aka
    CID-2289adbfa559.(CVE-2019-18809)

  - A memory leak in the ccp_run_sha_cmd() function in
    drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-128c66429247.(CVE-2019-18808)

  - A memory leak in the bfad_im_get_stats() function in
    drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka
    CID-0e62395da2bd.(CVE-2019-19066)

  - A memory leak in the ath9k_wmi_cmd() function in
    drivers/net/wireless/ath/ath9k/wmi.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption), aka
    CID-728c1e2a05e4.(CVE-2019-19074)

  - A vulnerability in the web server of Cisco Integrated
    Management Controller (IMC) could allow an
    authenticated, remote attacker to set sensitive
    configuration values and gain elevated privileges. The
    vulnerability is due to improper handling of substring
    comparison operations that are performed by the
    affected software. An attacker could exploit this
    vulnerability by sending a crafted HTTP request to the
    affected software. A successful exploit could allow the
    attacker with read-only privileges to gain
    administrator privileges.(CVE-2019-19073)

  - Two memory leaks in the rtl_usb_probe() function in
    drivers/net/wireless/realtek/rtlwifi/usb.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption), aka
    CID-3f9361695113.(CVE-2019-19063)

  - Two memory leaks in the mwifiex_pcie_init_evt_ring()
    function in drivers/net/wireless/marvell/mwifiex/pcie.c
    in the Linux kernel through 5.3.11 allow attackers to
    cause a denial of service (memory consumption) by
    triggering mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e.(CVE-2019-19057)

  - A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf()
    function in drivers/net/wireless/marvell/mwifiex/pcie.c
    in the Linux kernel through 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering mwifiex_map_pci_memory() failures, aka
    CID-db8fd2cde932.(CVE-2019-19056)

  - A memory leak in the gs_can_open() function in
    drivers/net/can/usb/gs_usb.c in the Linux kernel before
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering usb_submit_urb()
    failures, aka CID-fb5be6a7b486.(CVE-2019-19052)

  - An issue was discovered in the Linux kernel through
    5.3.9. There is a use-after-free when aa_label_parse()
    fails in aa_audit_rule_init() in
    security/apparmor/audit.c.(CVE-2019-18814)

  - Memory leaks in *clock_source_create() functions under
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
    aka CID-055e547478a1.(CVE-2019-19083)

  - Memory leaks in *create_resource_pool() functions under
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
    , aka CID-104c307147ad.(CVE-2019-19082)

  - A memory leak in the nfp_flower_spawn_vnic_reprs()
    function in
    drivers/net/ethernet/netronome/nfp/flower/main.c in the
    Linux kernel before 5.3.4 allows attackers to cause a
    denial of service (memory consumption), aka
    CID-8ce39eb5a67a.(CVE-2019-19081)

  - Four memory leaks in the nfp_flower_spawn_phy_reprs()
    function in
    drivers/net/ethernet/netronome/nfp/flower/main.c in the
    Linux kernel before 5.3.4 allow attackers to cause a
    denial of service (memory consumption), aka
    CID-8572cea1461a.(CVE-2019-19080)

  - A memory leak in the qrtr_tun_write_iter() function in
    net/qrtr/tun.c in the Linux kernel before 5.3 allows
    attackers to cause a denial of service (memory
    consumption), aka CID-a21b7f0cff19.(CVE-2019-19079)

  - A memory leak in the ath10k_usb_hif_tx_sg() function in
    drivers/net/wireless/ath/ath10k/usb.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    usb_submit_urb() failures, aka
    CID-b8d17e7d93d2.(CVE-2019-19078)

  - A memory leak in the bnxt_re_create_srq() function in
    drivers/infiniband/hw/bnxt_re/ib_verbs.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    copy to udata failures, aka
    CID-4a9d46a9fe14.(CVE-2019-19077)

  - A memory leak in the ca8210_probe() function in
    drivers/net/ieee802154/ca8210.c in the Linux kernel
    before 5.3.8 allows attackers to cause a denial of
    service (memory consumption) by triggering
    ca8210_get_platform_data() failures, aka
    CID-6402939ec86e.(CVE-2019-19075)

  - A memory leak in the rsi_send_beacon() function in
    drivers/net/wireless/rsi/rsi_91x_mgmt.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    rsi_prepare_beacon() failures, aka
    CID-d563131ef23c.(CVE-2019-19071)

  - A memory leak in the rtl8xxxu_submit_int_urb() function
    in
    drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c
    in the Linux kernel through 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering usb_submit_urb() failures, aka
    CID-a2cdd07488e6.(CVE-2019-19068)

  - ** DISPUTED ** Four memory leaks in the acp_hw_init()
    function in drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c in
    the Linux kernel before 5.3.8 allow attackers to cause
    a denial of service (memory consumption) by triggering
    mfd_add_hotplug_devices() or pm_genpd_add_device()
    failures, aka CID-57be09c6e874. NOTE: third parties
    dispute the relevance of this because the attacker must
    already have privileges for module
    loading.(CVE-2019-19067)

  - A memory leak in the sdma_init() function in
    drivers/infiniband/hw/hfi1/sdma.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption) by triggering
    rhashtable_init() failures, aka
    CID-34b3be18a04e.(CVE-2019-19065)

  - Multiple memory leaks in the
    iwl_pcie_ctxt_info_gen3_init() function in
    drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-gen3.
    c in the Linux kernel through 5.3.11 allow attackers to
    cause a denial of service (memory consumption) by
    triggering iwl_pcie_init_fw_sec() or
    dma_alloc_coherent() failures, aka
    CID-0f4f199443fa.(CVE-2019-19059)

  - A memory leak in the alloc_sgtable() function in
    drivers/net/wireless/intel/iwlwifi/fw/dbg.c in the
    Linux kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    alloc_page() failures, aka
    CID-b4b814fec1a5.(CVE-2019-19058)

  - A memory leak in the i2400m_op_rfkill_sw_toggle()
    function in drivers/net/wimax/i2400m/op-rfkill.c in the
    Linux kernel before 5.3.11 allows attackers to cause a
    denial of service (memory consumption), aka
    CID-6f3ef5c25cc7.(CVE-2019-19051)

  - A memory leak in the mlx5_fpga_conn_create_cq()
    function in
    drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c in
    the Linux kernel before 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering mlx5_vector2eqn() failures, aka
    CID-c8c2a057fdc7.(CVE-2019-19045)

  - A memory leak in the predicate_parse() function in
    kernel/trace/trace_events_filter.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-96c5c6e6a5b6.(CVE-2019-19072)

  - ** DISPUTED ** A memory leak in the spi_gpio_probe()
    function in drivers/spi/spi-gpio.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    devm_add_action_or_reset() failures, aka
    CID-d3b0ffa1d75d. NOTE: third parties dispute the
    relevance of this because the system must have already
    been out of memory before the probe
    began.(CVE-2019-19070)

  - ** DISPUTED ** A memory leak in the unittest_data_add()
    function in drivers/of/unittest.c in the Linux kernel
    before 5.3.10 allows attackers to cause a denial of
    service (memory consumption) by triggering
    of_fdt_unflatten_tree() failures, aka CID-e13de8fe0d6a.
    NOTE: third parties dispute the relevance of this
    because unittest.c can only be reached during
    boot.(CVE-2019-19049)

  - In the Linux kernel through 5.3.8, f->fmt.sdr.reserved
    is uninitialized in rcar_drif_g_fmt_sdr_cap in
    drivers/media/platform/rcar_drif.c, which could cause a
    memory disclosure problem.(CVE-2019-18786)

  - A memory leak in the cx23888_ir_probe() function in
    drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka
    CID-a7b2df76b42b.(CVE-2019-19054)

  - An issue was discovered in drivers/media/platform/vivid
    in the Linux kernel through 5.3.8. It is exploitable
    for privilege escalation on some Linux distributions
    where local users have /dev/video0 access, but only if
    the driver happens to be loaded. There are multiple
    race conditions during streaming stopping in this
    driver (part of the V4L2 subsystem). These issues are
    caused by wrong mutex locking in
    vivid_stop_generating_vid_cap(),
    vivid_stop_generating_vid_out(),
    sdr_cap_stop_streaming(), and the corresponding
    kthreads. At least one of these race conditions leads
    to a use-after-free.(CVE-2019-18683)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1042
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1dfef53");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.5.0");
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
if (uvp != "3.0.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h619.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h619.eulerosv2r8"];

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
