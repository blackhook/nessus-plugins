#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134486);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-0136",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-14835",
    "CVE-2019-15030",
    "CVE-2019-15031",
    "CVE-2019-15090",
    "CVE-2019-15098",
    "CVE-2019-15099",
    "CVE-2019-15212",
    "CVE-2019-15213",
    "CVE-2019-15215",
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15504",
    "CVE-2019-15918",
    "CVE-2019-15922",
    "CVE-2019-15923",
    "CVE-2019-15924",
    "CVE-2019-15926",
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
    "CVE-2019-18806",
    "CVE-2019-18808",
    "CVE-2019-18809",
    "CVE-2019-18813",
    "CVE-2019-18885",
    "CVE-2019-19066"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2020-1197)");
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
    output, etc. Security Fix(es):An issue was discovered
    in the Linux kernel before 5.2.3. There is a
    use-after-free caused by a malicious USB device in the
    drivers/media/usb/dvb-usb/dvb-usb-init.c
    driver.(CVE-2019-15213)An issue was discovered in the
    Linux kernel before 5.2.6. There is a use-after-free
    caused by a malicious USB device in the
    drivers/media/usb/cpia2/cpia2_usb.c
    driver.(CVE-2019-15215)An issue was discovered in the
    Linux kernel before 5.2.3. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/media/usb/zr364xx/zr364xx.c
    driver.(CVE-2019-15217)An issue was discovered in the
    Linux kernel before 5.1.8. There is a double-free
    caused by a malicious USB device in the
    drivers/usb/misc/rio500.c driver.(CVE-2019-15212)An
    issue was discovered in the Linux kernel before 5.0.14.
    There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/usb/misc/yurex.c
    driver.(CVE-2019-15216)An issue was discovered in
    drivers/scsi/qedi/qedi_dbg.c in the Linux kernel before
    5.1.12. In the qedi_dbg_* family of functions, there is
    an out-of-bounds read.(CVE-2019-15090)An issue was
    discovered in the Linux kernel before 5.0.9. There is a
    NULL pointer dereference for a cd data structure if
    alloc_disk fails in
    drivers/block/paride/pf.c.(CVE-2019-15923)An issue was
    discovered in the Linux kernel before 5.0.10.
    SMB2_negotiate in fs/cifs/smb2pdu.c has an
    out-of-bounds read because data structures are
    incompletely updated after a change from smb30 to
    smb21.(CVE-2019-15918)An issue was discovered in the
    Linux kernel before 5.0.9. There is a NULL pointer
    dereference for a pf data structure if alloc_disk fails
    in drivers/block/paride/pf.c.(CVE-2019-15922)An issue
    was discovered in the Linux kernel before 5.2.3. Out of
    bounds access exists in the functions
    ath6kl_wmi_pstream_timeout_event_rx and
    ath6kl_wmi_cac_event_rx in the file
    driverset/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)An
    issue was discovered in the Linux kernel before 5.0.11.
    fm10k_init_module in
    driverset/ethernet/intel/fm10k/fm10k_main.c has a NULL
    pointer dereference because there is no -ENOMEM upon an
    alloc_workqueue failure.(CVE-2019-15924)A buffer
    overflow flaw was found, in versions from 2.6.34 to
    5.2.x, in the way Linux kernel's vhost functionality
    that translates virtqueue buffers to IOVs, logged the
    buffer descriptors during migration. A privileged guest
    user able to pass descriptors with invalid length to
    the host when migration is underway, could use this
    flaw to increase their privileges on the
    host.(CVE-2019-14835)In the Linux kernel through 5.2.14
    on the powerpc platform, a local user can read vector
    registers of other users' processes via an interrupt.
    To exploit the venerability, a local user starts a
    transaction (via the hardware transactional memory
    instruction tbegin) and then accesses vector registers.
    At some point, the vector registers will be corrupted
    with the values from a different local Linux process,
    because MSR_TM_ACTIVE is misused in
    arch/powerpc/kernel/process.c.(CVE-2019-15031)In the
    Linux kernel through 5.2.14 on the powerpc platform, a
    local user can read vector registers of other users'
    processes via a Facility Unavailable exception. To
    exploit the venerability, a local user starts a
    transaction (via the hardware transactional memory
    instruction tbegin) and then accesses vector registers.
    At some point, the vector registers will be corrupted
    with the values from a different local Linux process
    because of a missing arch/powerpc/kernel/process.c
    check.(CVE-2019-15030)There is heap-based buffer
    overflow in kernel, all versions up to, excluding 5.3,
    in the marvell wifi chip driver in Linux kernel, that
    allows local users to cause a denial of service(system
    crash) or possibly execute arbitrary
    code.(CVE-2019-14816)A vulnerability was found in Linux
    Kernel, where a Heap Overflow was found in
    mwifiex_set_wmm_params() function of Marvell Wifi
    Driver.(CVE-2019-14815)There is heap-based buffer
    overflow in Linux kernel, all versions up to, excluding
    5.3, in the marvell wifi chip driver in Linux kernel,
    that allows local users to cause a denial of
    service(system crash) or possibly execute arbitrary
    code.(CVE-2019-14814)driverset/wireless/ath/ath10k/usb.
    c in the Linux kernel through 5.2.8 has a NULL pointer
    dereference via an incomplete address in an endpoint
    descriptor.(CVE-2019-15099)driverset/wireless/ath/ath6k
    l/usb.c in the Linux kernel through 5.2.8 has a NULL
    pointer dereference via an incomplete address in an
    endpoint
    descriptor.(CVE-2019-15098)driverset/wireless/rsi/rsi_9
    1x_usb.c in the Linux kernel through 5.2.9 has a Double
    Free via crafted USB device traffic (which may be
    remote via usbip or usbredir).CVE-2019-15504)In the
    Linux kernel before 5.2.14, rds6_inc_info_copy in
    net/rds/recv.c allows attackers to obtain sensitive
    information from kernel stack memory because tos and
    flags fields are not
    initialized.(CVE-2019-16714)drivers/scsi/qla2xxx/qla_os
    .c in the Linux kernel 5.2.14 does not check the
    alloc_workqueue return value, leading to a NULL pointer
    dereference.(CVE-2019-16233)An issue was discovered in
    the Linux kernel through 5.2.13. nbd_genl_status in
    drivers/blockbd.c does not check the
    nla_nest_start_noflag return
    value.(CVE-2019-16089)llcp_sock_create in
    netfc/llcp_sock.c in the AF_NFC network module in the
    Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-3a359798b176.(CVE-2019-17056)base_sock_create in
    drivers/isdn/mISDN/socket.c in the AF_ISDN network
    module in the Linux kernel through 5.3.2 does not
    enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-b91ee4aa2a21.(CVE-2019-17055)atalk_create in
    net/appletalk/ddp.c in the AF_APPLETALK network module
    in the Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-6cc03e8aa36c.(CVE-2019-17054)ieee802154_create in
    net/ieee802154/socket.c in the AF_IEEE802154 network
    module in the Linux kernel through 5.3.2 does not
    enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-e69dbd4619e7.(CVE-2019-17053)ax25_create in
    net/ax25/af_ax25.c in the AF_AX25 network module in the
    Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-0614e2b73768.(CVE-2019-17052)An issue was
    discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance.(CVE-2019-17075)rtl_p2p_noa_ie in
    driverset/wireless/realtek/rtlwifi/ps.c in the Linux
    kernel through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer overflow.(CVE-2019-17666)In the
    Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid
    in net/wireless/wext-sme.c does not reject a long SSID
    IE, leading to a Buffer Overflow.(CVE-2019-17133)An
    issue was discovered in net/wirelessl80211.c in the
    Linux kernel through 5.2.17. It does not check the
    length of variable elements in a beacon head, leading
    to a buffer overflow.(CVE-2019-16746)Insufficient
    access control in the Intel(R) PROSet/Wireless WiFi
    Software driver before version 21.10 may allow an
    unauthenticated user to potentially enable denial of
    service via adjacent
    access.(CVE-2019-0136)driverset/wireless/intel/iwlwifi/
    pcie/trans.c in the Linux kernel 5.2.14 does not check
    the alloc_workqueue return value, leading to a NULL
    pointer dereference.(CVE-2019-16234)A memory leak in
    the ql_alloc_large_buffers() function in
    driverset/ethernet/qlogic/qla3xxx.c in the Linux kernel
    before 5.3.5 allows local users to cause a denial of
    service (memory consumption) by triggering
    pci_dma_mapping_error() failures, aka
    CID-1acb8f2a7a9f.(CVE-2019-18806)A memory leak in the
    dwc3_pci_probe() function in
    drivers/usb/dwc3/dwc3-pci.c in the Linux kernel through
    5.3.9 allows attackers to cause a denial of service
    (memory consumption) by triggering
    platform_device_add_properties() failures, aka
    CID-9bbfceea12a8.(CVE-2019-18813)A memory leak in the
    af9005_identify_state() function in
    drivers/media/usb/dvb-usb/af9005.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-2289adbfa559.(CVE-2019-18809)fs/btrfs/volumes.c in
    the Linux kernel before 5.1 allows a
    btrfs_verify_dev_extents NULL pointer dereference via a
    crafted btrfs image because fs_devices->devices is
    mishandled within find_device, aka
    CID-09ba3bc9dd15.(CVE-2019-18885)A memory leak in the
    ccp_run_sha_cmd() function in
    drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-128c66429247.(CVE-2019-18808)A memory leak in the
    bfad_im_get_stats() function in
    drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka
    CID-0e62395da2bd.(CVE-2019-19066)Note:
    kernel-4.19.36-vhulk1907.1.0.h529 and earlier versions
    in EulerOS Virtualization for ARM 64 3.0.2.0 return
    incorrect time information when executing the uname -a
    command.

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1197
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0e492e5");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

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

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h529",
        "kernel-devel-4.19.36-vhulk1907.1.0.h529",
        "kernel-headers-4.19.36-vhulk1907.1.0.h529",
        "kernel-tools-4.19.36-vhulk1907.1.0.h529",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h529",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h529",
        "perf-4.19.36-vhulk1907.1.0.h529",
        "python-perf-4.19.36-vhulk1907.1.0.h529"];

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
