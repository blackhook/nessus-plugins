#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132360);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-1350",
    "CVE-2017-12134",
    "CVE-2018-1129",
    "CVE-2018-9465",
    "CVE-2019-10220",
    "CVE-2019-15291",
    "CVE-2019-17351",
    "CVE-2019-18675",
    "CVE-2019-18885",
    "CVE-2019-19051",
    "CVE-2019-19056",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19063",
    "CVE-2019-19065",
    "CVE-2019-19067",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19527",
    "CVE-2019-19528",
    "CVE-2019-19530",
    "CVE-2019-19531",
    "CVE-2019-19532",
    "CVE-2019-19533",
    "CVE-2019-19537",
    "CVE-2019-2215",
    "CVE-2019-9456"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-2693)");

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
    output, etc.Security Fix(es):Linux kernel CIFS
    implementation, version 4.9.0 is vulnerable to a
    relative paths injection in directory entry
    lists.(CVE-2019-10220)A memory leak in the
    i2400m_op_rfkill_sw_toggle() function in drivers/
    net/wimax/i2400m/op-rfkill.c in the Linux kernel before
    5.3.11 allows attackers to cause a denial of service
    (memory consumption), aka
    CID-6f3ef5c25cc7.(CVE-2019-19051)A memory leak in the
    sdma_init() function in
    drivers/infiniband/hw/hfi1/sdma.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption) by triggering
    rhashtable_init() failures, aka
    CID-34b3be18a04e.(CVE-2019-19065)Four memory leaks in
    the acp_hw_init() function in
    drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c in the Linux
    kernel before 5.3.8 allow attackers to cause a denial
    of service (memory consumption) by triggering
    mfd_add_hotplug_devices() or pm_genpd_add_device()
    failures, aka CID-57be09c6e874. NOTE: third parties
    dispute the relevance of this because the attacker must
    already have privileges for module
    loading.(CVE-2019-19067)An issue was discovered in
    drivers/xen/balloon.c in the Linux kernel before 5.2.3,
    as used in Xen through 4.12.x, allowing guest OS users
    to cause a denial of service because of unrestricted
    resource consumption during the mapping of guest
    memory, aka CID-6ef36ab967c7.(CVE-2019-17351)The
    xen_biovec_phys_mergeable function in
    drivers/xen/biomerge.c in Xen might allow local OS
    guest users to corrupt block device data streams and
    consequently obtain sensitive memory information, cause
    a denial of service, or gain host OS privileges by
    leveraging incorrect block IO merge-ability
    calculation.(CVE-2017-12134)In the Linux kernel before
    5.3.7, there is a use-after-free bug that can be caused
    by a malicious USB device in the
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
    the Linux kernel before 5.3.12, there is a
    use-after-free bug that can be caused by a malicious
    USB device in the drivers/input/ff-memless.c driver,
    aka CID-fa3a5a1880c9.(CVE-2019-19524)In the Linux
    kernel before 5.2.10, there is a use-after-free bug
    that can be caused by a malicious USB device in the
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
    drivers/hid/hid-zpff.c.(CVE-2019-19532)The VFS
    subsystem in the Linux kernel 3.x provides an
    incomplete set of requirements for setattr operations
    that underspecifies removing extended privilege
    attributes, which allows local users to cause a denial
    of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program.(CVE-2015-1350)In the Linux kernel
    before 5.2.9, there is a use-after-free bug that can be
    caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver, aka
    CID-fc05481b2fca.(CVE-2019-19531)The Linux kernel
    through 5.3.13 has a start_offset+size Integer Overflow
    in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has
    its own mmap implementation. This allows local users
    (with /dev/video0 access) to obtain read and write
    permissions on kernel physical pages, which can
    possibly result in a privilege
    escalation.(CVE-2019-18675)A flaw was found in the way
    signature calculation was handled by cephx
    authentication protocol. An attacker having access to
    ceph cluster network who is able to alter the message
    payload was able to bypass signature checks done by
    cephx protocol. Ceph branches master, mimic, luminous
    and jewel are believed to be
    vulnerable.(CVE-2018-1129)A memory leak in the
    alloc_sgtable() function in
    driverset/wireless/intel/iwlwifi/fw/dbg.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    alloc_page() failures, aka
    CID-b4b814fec1a5.(CVE-2019-19058)A memory leak in the
    ath9k_wmi_cmd() function in
    driverset/wireless/ath/ath9k/wmi.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-728c1e2a05e4.(CVE-2019-19074)Memory leaks in
    driverset/wireless/ath/ath9k/htc_hst.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption) by triggering
    wait_for_completion_timeout() failures. This affects
    the htc_config_pipe_credits() function, the
    htc_setup_complete() function, and the
    htc_connect_service() function, aka
    CID-853acf7caf10.(CVE-2019-19073)Two memory leaks in
    the rtl_usb_probe() function in
    driverset/wireless/realtek/rtlwifi/usb.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption), aka
    CID-3f9361695113.(CVE-2019-19063)A memory leak in the
    mwifiex_pcie_alloc_cmdrsp_buf() function in
    driverset/wireless/marvell/mwifiex/pcie.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    mwifiex_map_pci_memory() failures, aka
    CID-db8fd2cde932.(CVE-2019-19056)Two memory leaks in
    the mwifiex_pcie_init_evt_ring() function in
    driverset/wireless/marvell/mwifiex/pcie.c in the Linux
    kernel through 5.3.11 allow attackers to cause a denial
    of service (memory consumption) by triggering
    mwifiex_map_pci_memory() failures, aka
    CID-d10dcb615c8e.(CVE-2019-19057)An issue was
    discovered in the Linux kernel through 5.2.9. There is
    a NULL pointer dereference caused by a malicious USB
    device in the flexcop_usb_probe function in the
    drivers/media/usb/b2c2/flexcop-usb.c
    driver.(CVE-2019-15291)A use-after-free in binder.c
    allows an elevation of privilege from an application to
    the Linux Kernel. No user interaction is required to
    exploit this vulnerability, however exploitation does
    require either the installation of a malicious local
    application or a separate vulnerability in a network
    facing application.Product: AndroidAndroid ID:
    A-141720095(CVE-2019-2215)In task_get_unused_fd_flags
    of binder.c, there is a possible memory corruption due
    to a use after free. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation. Product: Android Versions: Android kernel
    Android ID: A-69164715 References: Upstream
    kernel.(CVE-2018-9465)In the Android kernel in Pixel C
    USB monitor driver there is a possible OOB write due to
    a missing bounds check. This could lead to local
    escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation.(CVE-2019-9456)fs/btrfs/volumes.c in the
    Linux kernel before 5.1 allows a
    btrfs_verify_dev_extents NULL pointer dereference via a
    crafted btrfs image because fs_devices->devices is
    mishandled within find_device, aka
    CID-09ba3bc9dd15.(CVE-2019-18885)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2693
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cacf951");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10220");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Binder Use-After-Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.5.h359.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h359.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h359.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h359.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h359.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h359.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h359.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
