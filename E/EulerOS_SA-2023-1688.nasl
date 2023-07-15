#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175217);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/07");

  script_cve_id(
    "CVE-2015-8558",
    "CVE-2016-9102",
    "CVE-2020-13754",
    "CVE-2020-13791",
    "CVE-2020-15469",
    "CVE-2020-15859",
    "CVE-2020-25742",
    "CVE-2020-25743",
    "CVE-2020-35503",
    "CVE-2021-3507",
    "CVE-2021-3713",
    "CVE-2021-3748",
    "CVE-2021-3750",
    "CVE-2021-3930",
    "CVE-2021-4206",
    "CVE-2021-20203",
    "CVE-2021-20255",
    "CVE-2021-20257",
    "CVE-2022-4144",
    "CVE-2022-26353"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.0 : qemu-kvm (EulerOS-SA-2023-1688)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - The ehci_process_itd function in hw/usb/hcd-ehci.c in QEMU allows local guest OS administrators to cause a
    denial of service (infinite loop and CPU consumption) via a circular isochronous transfer descriptor (iTD)
    list. (CVE-2015-8558)

  - Memory leak in the v9fs_xattrcreate function in hw/9pfs/9p.c in QEMU (aka Quick Emulator) allows local
    guest OS administrators to cause a denial of service (memory consumption and QEMU process crash) via a
    large number of Txattrcreate messages with the same fid number. (CVE-2016-9102)

  - hw/pci/msix.c in QEMU 4.2.0 allows guest OS users to trigger an out-of-bounds access via a crafted address
    in an msi-x mmio operation. (CVE-2020-13754)

  - hw/pci/pci.c in QEMU 4.2.0 allows guest OS users to trigger an out-of-bounds access by providing an
    address near the end of the PCI configuration space. (CVE-2020-13791)

  - In QEMU 4.2.0, a MemoryRegionOps object may lack read/write callback methods, leading to a NULL pointer
    dereference. (CVE-2020-15469)

  - QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e
    packet with the data's address set to the e1000e's MMIO address. (CVE-2020-15859)

  - pci_change_irq_level in hw/pci/pci.c in QEMU before 5.1.1 has a NULL pointer dereference because
    pci_get_bus() might not return a valid pointer. (CVE-2020-25742)

  - hw/ide/pci.c in QEMU before 5.1.1 can trigger a NULL pointer dereference because it lacks a pointer check
    before an ide_cancel_dma_sync call. (CVE-2020-25743)

  - A NULL pointer dereference flaw was found in the megasas-gen2 SCSI host bus adapter emulation of QEMU in
    versions before and including 6.0. This issue occurs in the megasas_command_cancelled() callback function
    while dropping a SCSI request. This flaw allows a privileged guest user to crash the QEMU process on the
    host, resulting in a denial of service. The highest threat from this vulnerability is to system
    availability. (CVE-2020-35503)

  - An integer overflow issue was found in the vmxnet3 NIC emulator of the QEMU for versions up to v5.2.0. It
    may occur if a guest was to supply invalid values for rx/tx queue size or other NIC parameters. A
    privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.
    (CVE-2021-20203)

  - A stack overflow via an infinite recursion vulnerability was found in the eepro100 i8255x device emulator
    of QEMU. This issue occurs while processing controller commands due to a DMA reentry issue. This flaw
    allows a guest user or process to consume CPU cycles or crash the QEMU process on the host, resulting in a
    denial of service. The highest threat from this vulnerability is to system availability. (CVE-2021-20255)

  - An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing
    transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid
    values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20257)

  - A heap buffer overflow was found in the floppy disk emulator of QEMU up to 6.0.0 (including). It could
    occur in fdctrl_transfer_handler() in hw/block/fdc.c while processing DMA read data transfers from the
    floppy drive to the guest system. A privileged guest user could use this flaw to crash the QEMU process on
    the host resulting in DoS scenario, or potential information leakage from the host memory. (CVE-2021-3507)

  - An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device emulation of QEMU in versions
    prior to 6.2.0-rc0. The device uses the guest supplied stream number unchecked, which can lead to out-of-
    bounds access to the UASDevice->data3 and UASDevice->status3 fields. A malicious guest user could use this
    flaw to crash QEMU or potentially achieve code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3713)

  - A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the
    descriptor's address belongs to the non direct access region, due to num_buffers being set after the
    virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a
    denial of service condition, or potentially execute code on the host with the privileges of the QEMU
    process. (CVE-2021-3748)

  - A DMA reentrancy issue was found in the USB EHCI controller emulation of QEMU. EHCI does not verify if the
    Buffer Pointer overlaps with its MMIO region when it transfers the USB packets. Crafted content may be
    written to the controller's registers and trigger undesirable actions (such as reset) while the device is
    still transferring packets. This can ultimately lead to a use-after-free issue. A malicious guest could
    use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or
    potentially execute arbitrary code within the context of the QEMU process on the host. This flaw affects
    QEMU versions before 7.0.0. (CVE-2021-3750)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A flaw was found in the QXL display device emulation in QEMU. An integer overflow in the cursor_alloc()
    function can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer
    overflow. This flaw allows a malicious privileged guest user to crash the QEMU process on the host or
    potentially execute arbitrary code within the context of the QEMU process. (CVE-2021-4206)

  - A flaw was found in the virtio-net device of QEMU. This flaw was inadvertently introduced with the fix for
    CVE-2021-3748, which forgot to unmap the cached virtqueue elements on error, leading to memory leakage and
    other unexpected results. Affected QEMU version: 6.2.0. (CVE-2022-26353)

  - An out-of-bounds read flaw was found in the QXL display device emulation in QEMU. The qxl_phys2virt()
    function does not check the size of the structure pointed to by the guest physical address, potentially
    reading past the end of the bar space into adjacent pages. A malicious guest user could use this flaw to
    crash the QEMU process on the host causing a denial of service condition. (CVE-2022-4144)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1688
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcea1827");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4206");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "qemu-img-2.8.1-30.161",
  "qemu-kvm-2.8.1-30.161",
  "qemu-kvm-common-2.8.1-30.161",
  "qemu-kvm-tools-2.8.1-30.161"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
